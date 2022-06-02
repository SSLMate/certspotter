// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.
//
// This file contains code from https://github.com/google/certificate-transparency/tree/master/go
// See ct/AUTHORS and ct/LICENSE for copyright and license information.

package certspotter

import (
	//	"container/list"
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/ct/client"
)

type ProcessCallback func(*Scanner, *ct.LogEntry)

// ScannerOptions holds configuration options for the Scanner
type ScannerOptions struct {
	// Number of entries to request in one batch from the Log
	BatchSize int

	// Number of concurrent proecssors to run
	NumWorkers int

	// Don't print any status messages to stdout
	Quiet bool
}

// Creates a new ScannerOptions struct with sensible defaults
func DefaultScannerOptions() *ScannerOptions {
	return &ScannerOptions{
		BatchSize:  1000,
		NumWorkers: 1,
		Quiet:      false,
	}
}

// Scanner is a tool to scan all the entries in a CT Log.
type Scanner struct {
	// Base URI of CT log
	LogUri string

	// Public key of the log
	publicKey crypto.PublicKey
	LogId     ct.SHA256Hash

	// Client used to talk to the CT log instance
	logClient *client.LogClient

	// Configuration options for this Scanner instance
	opts ScannerOptions
}

// fetchRange represents a range of certs to fetch from a CT log
type fetchRange struct {
	start int64
	end   int64
}

// Worker function to process certs.
// Accepts ct.LogEntries over the |entries| channel, and invokes processCert on them.
// Returns true over the |done| channel when the |entries| channel is closed.
func (s *Scanner) processerJob(id int, certsProcessed *int64, entries <-chan ct.LogEntry, processCert ProcessCallback, wg *sync.WaitGroup) {
	for entry := range entries {
		atomic.AddInt64(certsProcessed, 1)
		processCert(s, &entry)
	}
	wg.Done()
}

func (s *Scanner) fetch(r fetchRange, entries chan<- ct.LogEntry, tree *CollapsedMerkleTree) error {
	for r.start <= r.end {
		s.Log(fmt.Sprintf("Fetching entries %d to %d", r.start, r.end))
		logEntries, err := s.logClient.GetEntries(context.Background(), r.start, r.end)
		if err != nil {
			return err
		}
		for _, logEntry := range logEntries {
			if tree != nil {
				tree.Add(hashLeaf(logEntry.LeafBytes))
			}
			logEntry.Index = r.start
			entries <- logEntry
			r.start++
		}
	}
	return nil
}

// Worker function for fetcher jobs.
// Accepts cert ranges to fetch over the |ranges| channel, and if the fetch is
// successful sends the individual LeafInputs out into the
// |entries| channel for the processors to chew on.
// Will retry failed attempts to retrieve ranges indefinitely.
// Sends true over the |done| channel when the |ranges| channel is closed.
/* disabled becuase error handling is broken
func (s *Scanner) fetcherJob(id int, ranges <-chan fetchRange, entries chan<- ct.LogEntry, wg *sync.WaitGroup) {
	for r := range ranges {
		s.fetch(r, entries, nil)
	}
	wg.Done()
}
*/

// Returns the smaller of |a| and |b|
func min(a int64, b int64) int64 {
	if a < b {
		return a
	} else {
		return b
	}
}

// Returns the larger of |a| and |b|
func max(a int64, b int64) int64 {
	if a > b {
		return a
	} else {
		return b
	}
}

// Pretty prints the passed in number of |seconds| into a more human readable
// string.
func humanTime(seconds int) string {
	nanos := time.Duration(seconds) * time.Second
	hours := int(nanos / (time.Hour))
	nanos %= time.Hour
	minutes := int(nanos / time.Minute)
	nanos %= time.Minute
	seconds = int(nanos / time.Second)
	s := ""
	if hours > 0 {
		s += fmt.Sprintf("%d hours ", hours)
	}
	if minutes > 0 {
		s += fmt.Sprintf("%d minutes ", minutes)
	}
	if seconds > 0 {
		s += fmt.Sprintf("%d seconds ", seconds)
	}
	return s
}

func (s Scanner) Log(msg string) {
	if !s.opts.Quiet {
		log.Print(s.LogUri, ": ", msg)
	}
}

func (s Scanner) Warn(msg string) {
	log.Print(s.LogUri, ": ", msg)
}

func (s *Scanner) GetSTH() (*ct.SignedTreeHead, error) {
	latestSth, err := s.logClient.GetSTH(context.Background())
	if err != nil {
		return nil, err
	}
	if s.publicKey != nil {
		verifier, err := ct.NewSignatureVerifier(s.publicKey)
		if err != nil {
			return nil, err
		}
		if err := verifier.VerifySTHSignature(*latestSth); err != nil {
			return nil, errors.New("STH signature is invalid: " + err.Error())
		}
	}
	latestSth.LogID = s.LogId
	return latestSth, nil
}

func (s *Scanner) CheckConsistency(first *ct.SignedTreeHead, second *ct.SignedTreeHead) (bool, error) {
	if first.TreeSize == 0 || second.TreeSize == 0 {
		// RFC 6962 doesn't define how to generate a consistency proof in this case,
		// and it doesn't matter anyways since the tree is empty.  The DigiCert logs
		// return a 400 error if we ask for such a proof.
		return true, nil
	} else if first.TreeSize < second.TreeSize {
		proof, err := s.logClient.GetConsistencyProof(context.Background(), int64(first.TreeSize), int64(second.TreeSize))
		if err != nil {
			return false, err
		}
		return VerifyConsistencyProof(proof, first, second), nil
	} else if first.TreeSize > second.TreeSize {
		proof, err := s.logClient.GetConsistencyProof(context.Background(), int64(second.TreeSize), int64(first.TreeSize))
		if err != nil {
			return false, err
		}
		return VerifyConsistencyProof(proof, second, first), nil
	} else {
		// There is no need to ask the server for a consistency proof if the trees
		// are the same size, and the DigiCert log returns a 400 error if we try.
		return bytes.Equal(first.SHA256RootHash[:], second.SHA256RootHash[:]), nil
	}
}

func (s *Scanner) MakeCollapsedMerkleTree(sth *ct.SignedTreeHead) (*CollapsedMerkleTree, error) {
	if sth.TreeSize == 0 {
		return &CollapsedMerkleTree{}, nil
	}

	entries, err := s.logClient.GetEntries(context.Background(), int64(sth.TreeSize-1), int64(sth.TreeSize-1))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("Log did not return entry %d", sth.TreeSize-1)
	}
	leafHash := hashLeaf(entries[0].LeafBytes)

	var tree *CollapsedMerkleTree
	if sth.TreeSize > 1 {
		auditPath, _, err := s.logClient.GetAuditProof(context.Background(), leafHash, sth.TreeSize)
		if err != nil {
			return nil, err
		}
		reverseHashes(auditPath)
		tree, err = NewCollapsedMerkleTree(auditPath, sth.TreeSize-1)
		if err != nil {
			return nil, fmt.Errorf("Error returned bad audit proof for %x to %d", leafHash, sth.TreeSize)
		}
	} else {
		tree = EmptyCollapsedMerkleTree()
	}

	tree.Add(leafHash)
	if !bytes.Equal(tree.CalculateRoot(), sth.SHA256RootHash[:]) {
		return nil, fmt.Errorf("Calculated root hash does not match signed tree head at size %d", sth.TreeSize)
	}

	return tree, nil
}

func (s *Scanner) Scan(startIndex int64, endIndex int64, processCert ProcessCallback, tree *CollapsedMerkleTree) error {
	s.Log("Starting scan...")

	certsProcessed := new(int64)
	startTime := time.Now()
	/* TODO: only launch ticker goroutine if in verbose mode; kill the goroutine when the scanner finishes
	ticker := time.NewTicker(time.Second)
	go func() {
		for range ticker.C {
			throughput := float64(s.certsProcessed) / time.Since(startTime).Seconds()
			remainingCerts := int64(endIndex) - int64(startIndex) - s.certsProcessed
			remainingSeconds := int(float64(remainingCerts) / throughput)
			remainingString := humanTime(remainingSeconds)
			s.Log(fmt.Sprintf("Processed: %d certs (to index %d). Throughput: %3.2f ETA: %s", s.certsProcessed,
				startIndex+int64(s.certsProcessed), throughput, remainingString))
		}
	}()
	*/

	// Start processor workers
	jobs := make(chan ct.LogEntry, 100)
	var processorWG sync.WaitGroup
	for w := 0; w < s.opts.NumWorkers; w++ {
		processorWG.Add(1)
		go s.processerJob(w, certsProcessed, jobs, processCert, &processorWG)
	}

	for start := startIndex; start < int64(endIndex); {
		end := min(start+int64(s.opts.BatchSize), int64(endIndex)) - 1
		if err := s.fetch(fetchRange{start, end}, jobs, tree); err != nil {
			return err
		}
		start = end + 1
	}
	close(jobs)
	processorWG.Wait()
	s.Log(fmt.Sprintf("Completed %d certs in %s", *certsProcessed, humanTime(int(time.Since(startTime).Seconds()))))

	return nil
}

// Creates a new Scanner instance using |client| to talk to the log, and taking
// configuration options from |opts|.
func NewScanner(logUri string, logId ct.SHA256Hash, publicKey crypto.PublicKey, opts *ScannerOptions) *Scanner {
	var scanner Scanner
	scanner.LogUri = logUri
	scanner.LogId = logId
	scanner.publicKey = publicKey
	scanner.logClient = client.New(strings.TrimRight(logUri, "/"))
	scanner.opts = *opts
	return &scanner
}
