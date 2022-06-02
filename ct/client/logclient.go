// Package client is a CT log client implementation and contains types and code
// for interacting with RFC6962-compliant CT Log instances.
// See http://tools.ietf.org/html/rfc6962 for details
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	insecurerand "math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"software.sslmate.com/src/certspotter/ct"
)

const (
	baseRetryDelay = 1 * time.Second
	maxRetryDelay  = 120 * time.Second
	maxRetries     = 10
)

func isRetryableStatusCode(code int) bool {
	return code/100 == 5 || code == http.StatusTooManyRequests
}

func randomDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(insecurerand.Int63n(int64(max)-int64(min)+1))
}

func getRetryAfter(resp *http.Response) (time.Duration, bool) {
	if resp == nil {
		return 0, false
	}
	seconds, err := strconv.ParseUint(resp.Header.Get("Retry-After"), 10, 16)
	if err != nil {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func sleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// URI paths for CT Log endpoints
const (
	GetSTHPath            = "/ct/v1/get-sth"
	GetEntriesPath        = "/ct/v1/get-entries"
	GetSTHConsistencyPath = "/ct/v1/get-sth-consistency"
	GetProofByHashPath    = "/ct/v1/get-proof-by-hash"
	AddChainPath          = "/ct/v1/add-chain"
)

// LogClient represents a client for a given CT Log instance
type LogClient struct {
	uri        string       // the base URI of the log. e.g. http://ct.googleapis/pilot
	httpClient *http.Client // used to interact with the log via HTTP
}

//////////////////////////////////////////////////////////////////////////////////
// JSON structures follow.
// These represent the structures returned by the CT Log server.
//////////////////////////////////////////////////////////////////////////////////

// getSTHResponse respresents the JSON response to the get-sth CT method
type getSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`           // Number of certs in the current tree
	Timestamp         uint64 `json:"timestamp"`           // Time that the tree was created
	SHA256RootHash    []byte `json:"sha256_root_hash"`    // Root hash of the tree
	TreeHeadSignature []byte `json:"tree_head_signature"` // Log signature for this STH
}

// base64LeafEntry respresents a Base64 encoded leaf entry
type base64LeafEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

// getEntriesReponse respresents the JSON response to the CT get-entries method
type getEntriesResponse struct {
	Entries []base64LeafEntry `json:"entries"` // the list of returned entries
}

// getConsistencyProofResponse represents the JSON response to the CT get-consistency-proof method
type getConsistencyProofResponse struct {
	Consistency [][]byte `json:"consistency"`
}

// getAuditProofResponse represents the JSON response to the CT get-proof-by-hash method
type getAuditProofResponse struct {
	LeafIndex uint64   `json:"leaf_index"`
	AuditPath [][]byte `json:"audit_path"`
}

type addChainRequest struct {
	Chain [][]byte `json:"chain"`
}

type addChainResponse struct {
	SCTVersion uint8  `json:"sct_version"`
	ID         []byte `json:"id"`
	Timestamp  uint64 `json:"timestamp"`
	Extensions []byte `json:"extensions"`
	Signature  []byte `json:"signature"`
}

// New constructs a new LogClient instance.
// |uri| is the base URI of the CT log instance to interact with, e.g.
// http://ct.googleapis.com/pilot
func New(uri string) *LogClient {
	var c LogClient
	c.uri = uri
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			// We have to disable TLS certificate validation because because several logs
			// (WoSign, StartCom, GDCA) use certificates that are not widely trusted.
			// Since we verify that every response we receive from the log is signed
			// by the log's CT public key (either directly, or indirectly via the Merkle Tree),
			// TLS certificate validation is not actually necessary.  (We don't want to ship
			// our own trust store because that adds undesired complexity and would require
			// updating should a log ever change to a different CA.)
			InsecureSkipVerify: true,
		},
	}
	c.httpClient = &http.Client{Timeout: 60 * time.Second, Transport: transport}
	return &c
}

func (c *LogClient) fetchAndParse(ctx context.Context, uri string, respBody interface{}) error {
	return c.doAndParse(ctx, "GET", uri, nil, respBody)
}

func (c *LogClient) postAndParse(ctx context.Context, uri string, body interface{}, respBody interface{}) error {
	return c.doAndParse(ctx, "POST", uri, body, respBody)
}

func (c *LogClient) makeRequest(ctx context.Context, method string, uri string, body interface{}) (*http.Request, error) {
	if body == nil {
		return http.NewRequestWithContext(ctx, method, uri, nil)
	} else {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, uri, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
}

func (c *LogClient) doAndParse(ctx context.Context, method string, uri string, reqBody interface{}, respBody interface{}) error {
	numRetries := 0
retry:
	req, err := c.makeRequest(ctx, method, uri, reqBody)
	if err != nil {
		return fmt.Errorf("%s %s: error creating request: %w", method, uri, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.shouldRetry(ctx, numRetries, nil) {
			numRetries++
			goto retry
		}
		return err
	}
	respBodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		if c.shouldRetry(ctx, numRetries, nil) {
			numRetries++
			goto retry
		}
		return fmt.Errorf("%s %s: error reading response: %w", method, uri, err)
	}
	if resp.StatusCode/100 != 2 {
		if c.shouldRetry(ctx, numRetries, resp) {
			numRetries++
			goto retry
		}
		return fmt.Errorf("%s %s: %s (%s)", method, uri, resp.Status, string(respBodyBytes))
	}
	if err := json.Unmarshal(respBodyBytes, respBody); err != nil {
		return fmt.Errorf("%s %s: error parsing response JSON: %w", method, uri, err)
	}
	return nil
}

func (c *LogClient) shouldRetry(ctx context.Context, numRetries int, resp *http.Response) bool {
	if ctx.Err() != nil {
		return false
	}

	if numRetries == maxRetries {
		return false
	}

	if resp != nil && !isRetryableStatusCode(resp.StatusCode) {
		return false
	}

	var delay time.Duration
	if retryAfter, hasRetryAfter := getRetryAfter(resp); hasRetryAfter {
		delay = retryAfter
	} else {
		delay = baseRetryDelay * (1 << numRetries)
		if delay > maxRetryDelay {
			delay = maxRetryDelay
		}
		delay += randomDuration(0, delay/2)
	}

	if deadline, hasDeadline := ctx.Deadline(); hasDeadline && time.Now().Add(delay).After(deadline) {
		return false
	}

	return sleep(ctx, delay)
}

// GetSTH retrieves the current STH from the log.
// Returns a populated SignedTreeHead, or a non-nil error.
func (c *LogClient) GetSTH(ctx context.Context) (sth *ct.SignedTreeHead, err error) {
	var resp getSTHResponse
	if err = c.fetchAndParse(ctx, c.uri+GetSTHPath, &resp); err != nil {
		return
	}
	sth = &ct.SignedTreeHead{
		TreeSize:  resp.TreeSize,
		Timestamp: resp.Timestamp,
	}

	if len(resp.SHA256RootHash) != sha256.Size {
		return nil, fmt.Errorf("STH returned by server has invalid sha256_root_hash (expected length %d got %d)", sha256.Size, len(resp.SHA256RootHash))
	}
	copy(sth.SHA256RootHash[:], resp.SHA256RootHash)

	ds, err := ct.UnmarshalDigitallySigned(bytes.NewReader(resp.TreeHeadSignature))
	if err != nil {
		return nil, err
	}
	// TODO(alcutter): Verify signature
	sth.TreeHeadSignature = *ds
	return
}

// GetEntries attempts to retrieve the entries in the sequence [|start|, |end|] from the CT
// log server. (see section 4.6.)
// Returns a slice of LeafInputs or a non-nil error.
func (c *LogClient) GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error) {
	if end < 0 {
		return nil, errors.New("GetEntries: end should be >= 0")
	}
	if end < start {
		return nil, errors.New("GetEntries: start should be <= end")
	}
	var resp getEntriesResponse
	err := c.fetchAndParse(ctx, fmt.Sprintf("%s%s?start=%d&end=%d", c.uri, GetEntriesPath, start, end), &resp)
	if err != nil {
		return nil, err
	}
	entries := make([]ct.LogEntry, len(resp.Entries))
	for index, entry := range resp.Entries {
		leaf, err := ct.ReadMerkleTreeLeaf(bytes.NewBuffer(entry.LeafInput))
		if err != nil {
			return nil, fmt.Errorf("Reading Merkle Tree Leaf at index %d failed: %s", start+int64(index), err)
		}
		entries[index].LeafBytes = entry.LeafInput
		entries[index].Leaf = *leaf

		var chain []ct.ASN1Cert
		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			chain, err = ct.UnmarshalX509ChainArray(entry.ExtraData)

		case ct.PrecertLogEntryType:
			chain, err = ct.UnmarshalPrecertChainArray(entry.ExtraData)

		default:
			return nil, fmt.Errorf("Unknown entry type at index %d: %v", start+int64(index), leaf.TimestampedEntry.EntryType)
		}
		if err != nil {
			return nil, fmt.Errorf("Parsing entry of type %d at index %d failed: %s", leaf.TimestampedEntry.EntryType, start+int64(index), err)
		}
		entries[index].Chain = chain
		entries[index].Index = start + int64(index)
	}
	return entries, nil
}

// GetConsistencyProof retrieves a Merkle Consistency Proof between two STHs (|first| and |second|)
// from the log.  Returns a slice of MerkleTreeNodes (a ct.ConsistencyProof) or a non-nil error.
func (c *LogClient) GetConsistencyProof(ctx context.Context, first, second int64) (ct.ConsistencyProof, error) {
	if second < 0 {
		return nil, errors.New("GetConsistencyProof: second should be >= 0")
	}
	if second < first {
		return nil, errors.New("GetConsistencyProof: first should be <= second")
	}
	var resp getConsistencyProofResponse
	err := c.fetchAndParse(ctx, fmt.Sprintf("%s%s?first=%d&second=%d", c.uri, GetSTHConsistencyPath, first, second), &resp)
	if err != nil {
		return nil, err
	}
	nodes := make([]ct.MerkleTreeNode, len(resp.Consistency))
	for index, nodeBytes := range resp.Consistency {
		nodes[index] = nodeBytes
	}
	return nodes, nil
}

// GetAuditProof retrieves a Merkle Audit Proof (aka Inclusion Proof) for the given
// |hash| based on the STH at |treeSize| from the log.  Returns a slice of MerkleTreeNodes
// and the index of the leaf.
func (c *LogClient) GetAuditProof(ctx context.Context, hash ct.MerkleTreeNode, treeSize uint64) (ct.AuditPath, uint64, error) {
	var resp getAuditProofResponse
	err := c.fetchAndParse(ctx, fmt.Sprintf("%s%s?hash=%s&tree_size=%d", c.uri, GetProofByHashPath, url.QueryEscape(base64.StdEncoding.EncodeToString(hash)), treeSize), &resp)
	if err != nil {
		return nil, 0, err
	}
	path := make([]ct.MerkleTreeNode, len(resp.AuditPath))
	for index, nodeBytes := range resp.AuditPath {
		path[index] = nodeBytes
	}
	return path, resp.LeafIndex, nil
}

func (c *LogClient) AddChain(ctx context.Context, chain [][]byte) (*ct.SignedCertificateTimestamp, error) {
	req := addChainRequest{Chain: chain}

	var resp addChainResponse
	if err := c.postAndParse(ctx, c.uri+AddChainPath, &req, &resp); err != nil {
		return nil, err
	}

	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: ct.Version(resp.SCTVersion),
		Timestamp:  resp.Timestamp,
		Extensions: resp.Extensions,
	}

	if len(resp.ID) != sha256.Size {
		return nil, fmt.Errorf("SCT returned by server has invalid id (expected length %d got %d)", sha256.Size, len(resp.ID))
	}
	copy(sct.LogID[:], resp.ID)

	ds, err := ct.UnmarshalDigitallySigned(bytes.NewReader(resp.Signature))
	if err != nil {
		return nil, err
	}
	sct.Signature = *ds
	return sct, nil
}
