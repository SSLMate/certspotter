// Package client is a CT log client implementation and contains types and code
// for interacting with RFC6962-compliant CT Log instances.
// See http://tools.ietf.org/html/rfc6962 for details
package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mreiferson/go-httpclient"
	"software.sslmate.com/src/certspotter/ct"
)

// URI paths for CT Log endpoints
const (
	GetSTHPath            = "/ct/v1/get-sth"
	GetEntriesPath        = "/ct/v1/get-entries"
	GetSTHConsistencyPath = "/ct/v1/get-sth-consistency"
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

// New constructs a new LogClient instance.
// |uri| is the base URI of the CT log instance to interact with, e.g.
// http://ct.googleapis.com/pilot
func New(uri string) *LogClient {
	var c LogClient
	c.uri = uri
	transport := &httpclient.Transport{
		ConnectTimeout:        10 * time.Second,
		RequestTimeout:        30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
	}
	c.httpClient = &http.Client{Transport: transport}
	return &c
}

// Makes a HTTP call to |uri|, and attempts to parse the response as a JSON
// representation of the structure in |res|.
// Returns a non-nil |error| if there was a problem.
func (c *LogClient) fetchAndParse(uri string, res interface{}) error {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return err
	}
	//	req.Header.Set("Keep-Alive", "timeout=15, max=100")
	resp, err := c.httpClient.Do(req)
	var body []byte
	if resp != nil {
		body, err = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET %s: %s (%s)", uri, resp.Status, string(body))
	}
	if err = json.Unmarshal(body, &res); err != nil {
		return err
	}
	return nil
}

// GetSTH retrieves the current STH from the log.
// Returns a populated SignedTreeHead, or a non-nil error.
func (c *LogClient) GetSTH() (sth *ct.SignedTreeHead, err error) {
	var resp getSTHResponse
	if err = c.fetchAndParse(c.uri+GetSTHPath, &resp); err != nil {
		return
	}
	sth = &ct.SignedTreeHead{
		TreeSize:  resp.TreeSize,
		Timestamp: resp.Timestamp,
	}

	if len(resp.SHA256RootHash) != sha256.Size {
		return nil, fmt.Errorf("sha256_root_hash is invalid length, expected %d got %d", sha256.Size, len(resp.SHA256RootHash))
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
func (c *LogClient) GetEntries(start, end int64) ([]ct.LogEntry, error) {
	if end < 0 {
		return nil, errors.New("end should be >= 0")
	}
	if end < start {
		return nil, errors.New("start should be <= end")
	}
	var resp getEntriesResponse
	err := c.fetchAndParse(fmt.Sprintf("%s%s?start=%d&end=%d", c.uri, GetEntriesPath, start, end), &resp)
	if err != nil {
		return nil, err
	}
	entries := make([]ct.LogEntry, len(resp.Entries))
	for index, entry := range resp.Entries {
		leaf, err := ct.ReadMerkleTreeLeaf(bytes.NewBuffer(entry.LeafInput))
		if err != nil {
			return nil, err
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
			return nil, fmt.Errorf("saw unknown entry type: %v", leaf.TimestampedEntry.EntryType)
		}
		if err != nil {
			return nil, err
		}
		entries[index].Chain = chain
		entries[index].Index = start + int64(index)
	}
	return entries, nil
}

// GetConsistencyProof retrieves a Merkle Consistency Proof between two STHs (|first| and |second|)
// from the log.  Returns a slice of MerkleTreeNodes (a ct.ConsistencyProof) or a non-nil error.
func (c *LogClient) GetConsistencyProof(first, second int64) (ct.ConsistencyProof, error) {
	if second < 0 {
		return nil, errors.New("second should be >= 0")
	}
	if second < first {
		return nil, errors.New("first should be <= second")
	}
	var resp getConsistencyProofResponse
	err := c.fetchAndParse(fmt.Sprintf("%s%s?first=%d&second=%d", c.uri, GetSTHConsistencyPath, first, second), &resp)
	if err != nil {
		return nil, err
	}
	nodes := make([]ct.MerkleTreeNode, len(resp.Consistency))
	for index, nodeBytes := range resp.Consistency {
		nodes[index] = nodeBytes
	}
	return nodes, nil
}
