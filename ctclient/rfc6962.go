// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package ctclient

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/merkletree"
)

type RFC6962Log struct {
	URL        *url.URL
	HTTPClient *http.Client // nil to use default client
}

type RFC6962LogEntry struct {
	Leaf_input []byte `json:"leaf_input"`
	Extra_data []byte `json:"extra_data"`
}

func (ctlog *RFC6962Log) GetSTH(ctx context.Context) (*cttypes.SignedTreeHead, string, error) {
	fullURL := ctlog.URL.JoinPath("/ct/v1/get-sth").String()
	sth := new(cttypes.SignedTreeHead)
	if err := getJSON(ctx, ctlog.HTTPClient, fullURL, sth); err != nil {
		return nil, fullURL, err
	}
	return sth, fullURL, nil
}

func (ctlog *RFC6962Log) GetRoots(ctx context.Context) ([][]byte, error) {
	return getRoots(ctx, ctlog.HTTPClient, ctlog.URL)
}

func (ctlog *RFC6962Log) getEntries(ctx context.Context, startInclusive uint64, endInclusive uint64) ([]RFC6962LogEntry, error) {
	fullURL := ctlog.URL.JoinPath("/ct/v1/get-entries").String()
	fullURL += fmt.Sprintf("?start=%d&end=%d", startInclusive, endInclusive)

	var parsedResponse struct {
		Entries []RFC6962LogEntry `json:"entries"`
	}
	if err := getJSON(ctx, ctlog.HTTPClient, fullURL, &parsedResponse); err != nil {
		return nil, err
	}
	if len(parsedResponse.Entries) == 0 {
		return nil, fmt.Errorf("Get %q: zero entries returned", fullURL)
	}
	if uint64(len(parsedResponse.Entries)) > endInclusive-startInclusive+1 {
		return nil, fmt.Errorf("Get %q: extraneous entries returned", fullURL)
	}
	return parsedResponse.Entries, nil
}

func (ctlog *RFC6962Log) GetEntries(ctx context.Context, startInclusive uint64, endInclusive uint64) ([]Entry, error) {
	nativeEntries, err := ctlog.getEntries(ctx, startInclusive, endInclusive)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, len(nativeEntries))
	for i := range nativeEntries {
		entries[i] = &nativeEntries[i]
	}
	return entries, nil
}

type entryAndProofResponse struct {
	LeafInput []byte            `json:"leaf_input"`
	ExtraData []byte            `json:"extra_data"`
	AuditPath []merkletree.Hash `json:"audit_path"`
}

func (ctlog *RFC6962Log) getEntryAndProof(ctx context.Context, leafIndex uint64, treeSize uint64) (*entryAndProofResponse, error) {
	fullURL := ctlog.URL.JoinPath("/ct/v1/get-entry-and-proof").String()
	fullURL += fmt.Sprintf("?leaf_index=%d&tree_size=%d", leafIndex, treeSize)
	response := new(entryAndProofResponse)
	if err := getJSON(ctx, ctlog.HTTPClient, fullURL, response); err != nil {
		return nil, err
	}
	return response, nil
}

type proofResponse struct {
	LeafIndex uint64            `json:"leaf_index"`
	AuditPath []merkletree.Hash `json:"audit_path"`
}

func (ctlog *RFC6962Log) getProofByHash(ctx context.Context, hash *merkletree.Hash, treeSize uint64) (*proofResponse, error) {
	fullURL := ctlog.URL.JoinPath("/ct/v1/get-proof-by-hash").String()
	fullURL += fmt.Sprintf("?hash=%s&tree_size=%d", url.QueryEscape(hash.Base64String()), treeSize)
	response := new(proofResponse)
	if err := getJSON(ctx, ctlog.HTTPClient, fullURL, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (ctlog *RFC6962Log) reconstructTree(ctx context.Context, treeSize uint64) (*merkletree.CollapsedTree, error) {
	if treeSize == 0 {
		return new(merkletree.CollapsedTree), nil
	}
	if entryAndProof, err := ctlog.getEntryAndProof(ctx, treeSize-1, treeSize); err == nil {
		tree := new(merkletree.CollapsedTree)
		slices.Reverse(entryAndProof.AuditPath)
		if err := tree.Init(entryAndProof.AuditPath, treeSize-1); err != nil {
			return nil, fmt.Errorf("log returned invalid audit proof for entry %d to STH %d: %w", treeSize-1, treeSize, err)
		}
		tree.Add(merkletree.HashLeaf(entryAndProof.LeafInput))
		return tree, nil
	}
	entries, err := ctlog.getEntries(ctx, treeSize-1, treeSize-1)
	if err != nil {
		return nil, err
	}
	leafHash := merkletree.HashLeaf(entries[0].Leaf_input)
	tree := new(merkletree.CollapsedTree)
	if treeSize > 1 {
		response, err := ctlog.getProofByHash(ctx, &leafHash, treeSize)
		if err != nil {
			return nil, err
		}
		if response.LeafIndex != treeSize-1 {
			// This can happen if the leaf hash is present in the tree in more than one place. Unfortunately, we can't reconstruct when tree if this happens. Fortunately, this is really unlikely, and most logs support get-entry-and-proof anyways.
			return nil, fmt.Errorf("unable to reconstruct tree because leaf hash %s is present in tree at more than one index (need proof for index %d but get-proof-by-hash returned proof for index %d)", leafHash.Base64String(), treeSize-1, response.LeafIndex)
		}
		slices.Reverse(response.AuditPath)
		if err := tree.Init(response.AuditPath, treeSize-1); err != nil {
			return nil, fmt.Errorf("log returned invalid audit proof for hash %s to STH %d: %w", leafHash.Base64String(), treeSize, err)
		}
	}
	tree.Add(leafHash)
	return tree, nil
}

func (ctlog *RFC6962Log) ReconstructTree(ctx context.Context, sth *cttypes.SignedTreeHead) (*merkletree.CollapsedTree, error) {
	tree, err := ctlog.reconstructTree(ctx, sth.TreeSize)
	if err != nil {
		return nil, err
	}

	if rootHash := tree.CalculateRoot(); rootHash != sth.RootHash {
		return nil, fmt.Errorf("calculated root hash (%s) does not match STH (%s) at size %d", rootHash.Base64String(), sth.RootHash.Base64String(), sth.TreeSize)
	}

	return tree, nil
}

func (entry *RFC6962LogEntry) isX509() bool {
	return len(entry.Leaf_input) >= 12 && entry.Leaf_input[0] == 0 && entry.Leaf_input[1] == 0 && entry.Leaf_input[10] == 0 && entry.Leaf_input[11] == 0
}

func (entry *RFC6962LogEntry) isPrecert() bool {
	return len(entry.Leaf_input) >= 12 && entry.Leaf_input[0] == 0 && entry.Leaf_input[1] == 0 && entry.Leaf_input[10] == 0 && entry.Leaf_input[11] == 1
}

func (entry *RFC6962LogEntry) LeafInput() []byte {
	return entry.Leaf_input
}

func (entry *RFC6962LogEntry) ExtraData(context.Context, IssuerGetter) ([]byte, error) {
	return entry.Extra_data, nil
}

func (entry *RFC6962LogEntry) Precertificate() (cttypes.ASN1Cert, error) {
	if !entry.isPrecert() {
		return nil, fmt.Errorf("not a precertificate entry")
	}
	extraData, err := cttypes.ParseExtraDataForPrecertEntry(entry.Extra_data)
	if err != nil {
		return nil, fmt.Errorf("error parsing extra_data: %w", err)
	}
	return extraData.PreCertificate, nil
}

func (entry *RFC6962LogEntry) ChainFingerprints() ([][32]byte, error) {
	chain, err := entry.parseChain()
	if err != nil {
		return nil, err
	}
	fingerprints := make([][32]byte, len(chain))
	for i := range chain {
		fingerprints[i] = sha256.Sum256(chain[i])
	}
	return fingerprints, nil
}

func (entry *RFC6962LogEntry) GetChain(context.Context, IssuerGetter) (cttypes.ASN1CertChain, error) {
	return entry.parseChain()
}

func (entry *RFC6962LogEntry) parseChain() (cttypes.ASN1CertChain, error) {
	switch {
	case entry.isX509():
		extraData, err := cttypes.ParseExtraDataForX509Entry(entry.Extra_data)
		if err != nil {
			return nil, fmt.Errorf("error parsing extra_data for X509 entry: %w", err)
		}
		return extraData, nil
	case entry.isPrecert():
		extraData, err := cttypes.ParseExtraDataForPrecertEntry(entry.Extra_data)
		if err != nil {
			return nil, fmt.Errorf("error parsing extra_data for precert entry: %w", err)
		}
		return extraData.PrecertificateChain, nil
	default:
		return nil, fmt.Errorf("unknown entry type")
	}
}
