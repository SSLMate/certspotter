// Copyright (C) 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/ct/client"
	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/certspotter/merkletree"
)

const (
	maxGetEntriesSize  = 1000
	monitorLogInterval = 5 * time.Minute
)

func isFatalLogError(err error) bool {
	return errors.Is(err, context.Canceled)
}

func newLogClient(ctlog *loglist.Log) (*client.LogClient, error) {
	logKey, err := x509.ParsePKIXPublicKey(ctlog.Key)
	if err != nil {
		return nil, fmt.Errorf("error parsing log key: %w", err)
	}
	verifier, err := ct.NewSignatureVerifier(logKey)
	if err != nil {
		return nil, fmt.Errorf("error with log key: %w", err)
	}
	return client.NewWithVerifier(strings.TrimRight(ctlog.URL, "/"), verifier), nil
}

func monitorLogContinously(ctx context.Context, config *Config, ctlog *loglist.Log) error {
	logClient, err := newLogClient(ctlog)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(monitorLogInterval)
	defer ticker.Stop()

	for ctx.Err() == nil {
		if err := monitorLog(ctx, config, ctlog, logClient); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return ctx.Err()
}

func monitorLog(ctx context.Context, config *Config, ctlog *loglist.Log, logClient *client.LogClient) (returnedErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		stateDirPath     = filepath.Join(config.StateDir, "logs", ctlog.LogID.Base64URLString())
		stateFilePath    = filepath.Join(stateDirPath, "state.json")
		sthsDirPath      = filepath.Join(stateDirPath, "unverified_sths")
		malformedDirPath = filepath.Join(stateDirPath, "malformed_entries")
	)
	for _, dirPath := range []string{stateDirPath, sthsDirPath, malformedDirPath} {
		if err := os.Mkdir(dirPath, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("error creating state directory: %w", err)
		}
	}

	startTime := time.Now()
	latestSTH, err := logClient.GetSTH(ctx)
	if isFatalLogError(err) {
		return err
	} else if err != nil {
		recordError(fmt.Errorf("error fetching latest STH for %s: %w", ctlog.URL, err))
		return nil
	}
	latestSTH.LogID = ctlog.LogID
	if err := storeSTHInDir(sthsDirPath, latestSTH); err != nil {
		return fmt.Errorf("error storing latest STH: %w", err)
	}

	state, err := loadStateFile(stateFilePath)
	if errors.Is(err, fs.ErrNotExist) {
		if config.StartAtEnd {
			tree, err := reconstructTree(ctx, logClient, latestSTH)
			if isFatalLogError(err) {
				return err
			} else if err != nil {
				recordError(fmt.Errorf("error reconstructing tree of size %d for %s: %w", latestSTH.TreeSize, ctlog.URL, err))
				return nil
			}
			state = &stateFile{
				DownloadPosition: tree,
				VerifiedPosition: tree,
				VerifiedSTH:      latestSTH,
				LastSuccess:      startTime.UTC(),
			}
		} else {
			state = &stateFile{
				DownloadPosition: merkletree.EmptyCollapsedTree(),
				VerifiedPosition: merkletree.EmptyCollapsedTree(),
				VerifiedSTH:      nil,
				LastSuccess:      startTime.UTC(),
			}
		}
		if config.Verbose {
			log.Printf("brand new log %s (starting from %d)", ctlog.URL, state.DownloadPosition.Size())
		}
		if err := state.store(stateFilePath); err != nil {
			return fmt.Errorf("error storing state file: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("error loading state file: %w", err)
	}

	sths, err := loadSTHsFromDir(sthsDirPath)
	if err != nil {
		return fmt.Errorf("error loading STHs directory: %w", err)
	}

	for len(sths) > 0 && sths[0].TreeSize <= state.DownloadPosition.Size() {
		// TODO-4: audit sths[0] against state.VerifiedSTH
		if err := removeSTHFromDir(sthsDirPath, sths[0]); err != nil {
			return fmt.Errorf("error removing STH: %w", err)
		}
		sths = sths[1:]
	}

	defer func() {
		if config.Verbose {
			log.Printf("saving state in defer for %s", ctlog.URL)
		}
		if err := state.store(stateFilePath); err != nil && returnedErr == nil {
			returnedErr = fmt.Errorf("error storing state file: %w", err)
		}
	}()

	if len(sths) == 0 {
		state.LastSuccess = startTime.UTC()
		return nil
	}

	var (
		downloadBegin = state.DownloadPosition.Size()
		downloadEnd   = sths[len(sths)-1].TreeSize
		entries       = make(chan client.GetEntriesItem, maxGetEntriesSize)
		downloadErr   error
	)
	if config.Verbose {
		log.Printf("downloading entries from %s in range [%d, %d)", ctlog.URL, downloadBegin, downloadEnd)
	}
	go func() {
		defer close(entries)
		downloadErr = downloadEntries(ctx, logClient, entries, downloadBegin, downloadEnd)
	}()
	for rawEntry := range entries {
		entry := &logEntry{
			Log:       ctlog,
			Index:     state.DownloadPosition.Size(),
			LeafInput: rawEntry.LeafInput,
			ExtraData: rawEntry.ExtraData,
			LeafHash:  merkletree.HashLeaf(rawEntry.LeafInput),
		}
		if err := processLogEntry(ctx, config, entry); err != nil {
			return fmt.Errorf("error processing entry %d: %w", entry.Index, err)
		}

		state.DownloadPosition.Add(entry.LeafHash)
		rootHash := state.DownloadPosition.CalculateRoot()
		shouldSaveState := state.DownloadPosition.Size()%10000 == 0

		for len(sths) > 0 && state.DownloadPosition.Size() == sths[0].TreeSize {
			if merkletree.Hash(sths[0].SHA256RootHash) != rootHash {
				recordError(fmt.Errorf("error verifying %s at tree size %d: the STH root hash (%x) does not match the entries returned by the log (%x)", ctlog.URL, sths[0].TreeSize, sths[0].SHA256RootHash, rootHash))

				state.DownloadPosition = state.VerifiedPosition
				if err := state.store(stateFilePath); err != nil {
					return fmt.Errorf("error storing state file: %w", err)
				}
				return nil
			}

			state.VerifiedPosition = state.DownloadPosition
			state.VerifiedSTH = sths[0]
			shouldSaveState = true
			if err := removeSTHFromDir(sthsDirPath, sths[0]); err != nil {
				return fmt.Errorf("error removing verified STH: %w", err)
			}

			sths = sths[1:]
		}

		if shouldSaveState {
			if err := state.store(stateFilePath); err != nil {
				return fmt.Errorf("error storing state file: %w", err)
			}
		}
	}

	if isFatalLogError(downloadErr) {
		return downloadErr
	} else if downloadErr != nil {
		recordError(fmt.Errorf("error downloading entries from %s: %w", ctlog.URL, downloadErr))
		return nil
	}

	if config.Verbose {
		log.Printf("finished downloading entries from %s", ctlog.URL)
	}

	state.LastSuccess = startTime.UTC()
	return nil
}

func downloadEntries(ctx context.Context, logClient *client.LogClient, entriesChan chan<- client.GetEntriesItem, begin, end uint64) error {
	for begin < end && ctx.Err() == nil {
		size := begin - end
		if size > maxGetEntriesSize {
			size = maxGetEntriesSize
		}
		entries, err := logClient.GetRawEntries(ctx, begin, begin+size-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case entriesChan <- entry:
			}
		}
		begin += uint64(len(entries))
	}
	return ctx.Err()
}

func reconstructTree(ctx context.Context, logClient *client.LogClient, sth *ct.SignedTreeHead) (*merkletree.CollapsedTree, error) {
	if sth.TreeSize == 0 {
		return merkletree.EmptyCollapsedTree(), nil
	}
	entries, err := logClient.GetRawEntries(ctx, sth.TreeSize-1, sth.TreeSize-1)
	if err != nil {
		return nil, err
	}
	leafHash := merkletree.HashLeaf(entries[0].LeafInput)

	var tree *merkletree.CollapsedTree
	if sth.TreeSize > 1 {
		auditPath, _, err := logClient.GetAuditProof(ctx, leafHash[:], sth.TreeSize)
		if err != nil {
			return nil, err
		}
		hashes := make([]merkletree.Hash, len(auditPath))
		for i := range hashes {
			copy(hashes[i][:], auditPath[len(auditPath)-i-1])
		}
		tree, err = merkletree.NewCollapsedTree(hashes, sth.TreeSize-1)
		if err != nil {
			return nil, fmt.Errorf("log returned invalid audit proof for %x to %d: %w", leafHash, sth.TreeSize, err)
		}
	} else {
		tree = merkletree.EmptyCollapsedTree()
	}

	tree.Add(leafHash)
	rootHash := tree.CalculateRoot()
	if rootHash != merkletree.Hash(sth.SHA256RootHash) {
		return nil, fmt.Errorf("calculated root hash (%x) does not match signed tree head (%x) at size %d", rootHash, sth.SHA256RootHash, sth.TreeSize)
	}

	return tree, nil
}
