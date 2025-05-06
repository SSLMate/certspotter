// Copyright (C) 2025 Opsmate, Inc.
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
	"errors"
	"fmt"
	"golang.org/x/sync/errgroup"
	"log"
	mathrand "math/rand/v2"
	"net/url"
	"slices"
	"time"

	"software.sslmate.com/src/certspotter/ctclient"
	"software.sslmate.com/src/certspotter/ctcrypto"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/certspotter/merkletree"
	"software.sslmate.com/src/certspotter/sequencer"
)

const (
	getSTHInterval = 5 * time.Minute
)

func downloadJobSize(ctlog *loglist.Log) uint64 {
	if ctlog.IsStaticCTAPI() {
		return ctclient.StaticTileWidth
	} else if ctlog.CertspotterDownloadSize != 0 {
		return uint64(ctlog.CertspotterDownloadSize)
	} else {
		return 1000
	}
}

func downloadWorkers(ctlog *loglist.Log) int {
	if ctlog.CertspotterDownloadJobs != 0 {
		return ctlog.CertspotterDownloadJobs
	} else {
		return 1
	}
}

type verifyEntriesError struct {
	sth             *cttypes.SignedTreeHead
	entriesRootHash merkletree.Hash
}

func (e *verifyEntriesError) Error() string {
	return fmt.Sprintf("error verifying at tree size %d: the STH root hash (%x) does not match the entries returned by the log (%x)", e.sth.TreeSize, e.sth.RootHash, e.entriesRootHash)
}

func withRetry(ctx context.Context, maxRetries int, f func() error) error {
	const minSleep = 1 * time.Second
	const maxSleep = 10 * time.Minute

	numRetries := 0
	for ctx.Err() == nil {
		err := f()
		if err == nil || errors.Is(err, context.Canceled) {
			return err
		}
		if maxRetries != -1 && numRetries >= maxRetries {
			return fmt.Errorf("%w (retried %d times)", err, numRetries)
		}
		upperBound := min(minSleep*(1<<numRetries)*2, maxSleep)
		lowerBound := max(upperBound/2, minSleep)
		sleepTime := lowerBound + mathrand.N(upperBound-lowerBound)
		if err := sleep(ctx, sleepTime); err != nil {
			return err
		}
		numRetries++
	}
	return ctx.Err()
}

func getEntriesFull(ctx context.Context, client ctclient.Log, startInclusive, endExclusive uint64) ([]ctclient.Entry, error) {
	allEntries := make([]ctclient.Entry, 0, endExclusive-startInclusive)
	for startInclusive < endExclusive {
		entries, err := client.GetEntries(ctx, startInclusive, endExclusive-1)
		if err != nil {
			return nil, err
		}
		allEntries = append(allEntries, entries...)
		startInclusive += uint64(len(entries))
	}
	return allEntries, nil
}

func getAndVerifySTH(ctx context.Context, ctlog *loglist.Log, client ctclient.Log) (*cttypes.SignedTreeHead, string, error) {
	sth, url, err := client.GetSTH(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("error getting STH: %w", err)
	}
	if err := ctcrypto.PublicKey(ctlog.Key).Verify(ctcrypto.SignatureInputForSTH(sth), sth.Signature); err != nil {
		return nil, "", fmt.Errorf("STH has invalid signature: %w", err)
	}
	return sth, url, nil
}

type logClient struct {
	log    *loglist.Log
	client ctclient.Log
}

func (client *logClient) GetSTH(ctx context.Context) (sth *cttypes.SignedTreeHead, url string, err error) {
	err = withRetry(ctx, -1, func() error {
		sth, url, err = getAndVerifySTH(ctx, client.log, client.client)
		return err
	})
	return
}
func (client *logClient) GetRoots(ctx context.Context) (roots [][]byte, err error) {
	err = withRetry(ctx, -1, func() error {
		roots, err = client.client.GetRoots(ctx)
		return err
	})
	return
}
func (client *logClient) GetEntries(ctx context.Context, startInclusive, endInclusive uint64) (entries []ctclient.Entry, err error) {
	err = withRetry(ctx, -1, func() error {
		entries, err = client.client.GetEntries(ctx, startInclusive, endInclusive)
		return err
	})
	return
}
func (client *logClient) ReconstructTree(ctx context.Context, sth *cttypes.SignedTreeHead) (tree *merkletree.CollapsedTree, err error) {
	err = withRetry(ctx, -1, func() error {
		tree, err = client.client.ReconstructTree(ctx, sth)
		return err
	})
	return
}

type issuerGetter struct {
	state     StateProvider
	logGetter ctclient.IssuerGetter
}

func (ig *issuerGetter) GetIssuer(ctx context.Context, fingerprint *[32]byte) ([]byte, error) {
	if issuer, err := ig.state.LoadIssuer(ctx, fingerprint); err != nil {
		log.Printf("error loading cached issuer %x (issuer will be retrieved from log instead): %s", *fingerprint, err)
	} else if issuer != nil {
		return issuer, nil
	}

	var issuer []byte
	if err := withRetry(ctx, 7, func() error {
		var err error
		issuer, err = ig.logGetter.GetIssuer(ctx, fingerprint)
		return err
	}); err != nil {
		return nil, err
	}

	if err := ig.state.StoreIssuer(ctx, fingerprint, issuer); err != nil {
		log.Printf("error caching issuer %x (issuer will be re-retrieved from log in the future): %s", *fingerprint, err)
	}

	return issuer, nil
}

func newLogClient(config *Config, ctlog *loglist.Log) (ctclient.Log, ctclient.IssuerGetter, error) {
	switch {
	case ctlog.IsRFC6962():
		logURL, err := url.Parse(ctlog.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid URL: %w", err)
		}
		return &logClient{
			log:    ctlog,
			client: &ctclient.RFC6962Log{URL: logURL},
		}, nil, nil
	case ctlog.IsStaticCTAPI():
		submissionURL, err := url.Parse(ctlog.SubmissionURL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid submission URL: %w", err)
		}
		monitoringURL, err := url.Parse(ctlog.MonitoringURL)
		if err != nil {
			return nil, nil, fmt.Errorf("log has invalid monitoring URL: %w", err)
		}
		client := &ctclient.StaticLog{
			SubmissionURL: submissionURL,
			MonitoringURL: monitoringURL,
			ID:            ctlog.LogID,
		}
		return &logClient{
				log:    ctlog,
				client: client,
			}, &issuerGetter{
				state:     config.State,
				logGetter: client,
			}, nil
	default:
		return nil, nil, fmt.Errorf("log uses unknown protocol")
	}
}

func monitorLogContinously(ctx context.Context, config *Config, ctlog *loglist.Log) (returnedErr error) {
	client, issuerGetter, err := newLogClient(config, ctlog)
	if err != nil {
		return err
	}
	if err := config.State.PrepareLog(ctx, ctlog.LogID); err != nil {
		return fmt.Errorf("error preparing state: %w", err)
	}
	state, err := config.State.LoadLogState(ctx, ctlog.LogID)
	if err != nil {
		return fmt.Errorf("error loading log state: %w", err)
	}
	if state == nil {
		if config.StartAtEnd {
			sth, _, err := client.GetSTH(ctx)
			if err != nil {
				return err
			}
			tree, err := client.ReconstructTree(ctx, sth)
			if err != nil {
				return err
			}
			state = &LogState{
				DownloadPosition: tree,
				VerifiedPosition: tree,
				VerifiedSTH:      sth,
				LastSuccess:      time.Now(),
			}
		} else {
			state = &LogState{
				DownloadPosition: merkletree.EmptyCollapsedTree(),
				VerifiedPosition: merkletree.EmptyCollapsedTree(),
				VerifiedSTH:      nil,
				LastSuccess:      time.Now(),
			}
		}
		if config.Verbose {
			log.Printf("brand new log %s (starting from %d)", ctlog.GetMonitoringURL(), state.DownloadPosition.Size())
		}
		if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
			return fmt.Errorf("error storing log state: %w", err)
		}
	}

	defer func() {
		if config.Verbose {
			log.Printf("saving state in defer for %s", ctlog.GetMonitoringURL())
		}
		storeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := config.State.StoreLogState(storeCtx, ctlog.LogID, state); err != nil && returnedErr == nil {
			returnedErr = fmt.Errorf("error storing log state: %w", err)
		}
	}()

retry:
	position := state.DownloadPosition.Size()

	// generateBatchesWorker ==> downloadWorker ==> processWorker ==> saveStateWorker

	batches := make(chan *batch, downloadWorkers(ctlog))
	processedBatches := sequencer.New[batch](0, uint64(downloadWorkers(ctlog))*10)

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return getSTHWorker(gctx, config, ctlog, client) })
	group.Go(func() error { return generateBatchesWorker(gctx, config, ctlog, position, batches) })
	for range downloadWorkers(ctlog) {
		downloadedBatches := make(chan *batch, 1)
		group.Go(func() error { return downloadWorker(gctx, config, ctlog, client, batches, downloadedBatches) })
		group.Go(func() error {
			return processWorker(gctx, config, ctlog, issuerGetter, downloadedBatches, processedBatches)
		})
	}
	group.Go(func() error { return saveStateWorker(gctx, config, ctlog, state, processedBatches) })

	err = group.Wait()
	if verifyErr := (*verifyEntriesError)(nil); errors.As(err, &verifyErr) {
		recordError(ctx, config, ctlog, verifyErr)
		state.rewindDownloadPosition()
		if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
			return fmt.Errorf("error storing log state: %w", err)
		}
		if err := sleep(ctx, 5*time.Minute); err != nil {
			return err
		}
		goto retry
	}
	return err
}

func getSTHWorker(ctx context.Context, config *Config, ctlog *loglist.Log, client ctclient.Log) error {
	for ctx.Err() == nil {
		sth, _, err := client.GetSTH(ctx)
		if err != nil {
			return err
		}
		if err := config.State.StoreSTH(ctx, ctlog.LogID, sth); err != nil {
			return fmt.Errorf("error storing STH: %w", err)
		}
		if err := sleep(ctx, getSTHInterval); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type batch struct {
	number     uint64
	begin, end uint64
	sths       []*StoredSTH     // STHs with sizes in range [begin,end], sorted by TreeSize
	entries    []ctclient.Entry // in range [begin,end)
}

func generateBatchesWorker(ctx context.Context, config *Config, ctlog *loglist.Log, position uint64, batches chan<- *batch) error {
	ticker := time.NewTicker(15 * time.Second)
	var number uint64
	for ctx.Err() == nil {
		sths, err := config.State.LoadSTHs(ctx, ctlog.LogID)
		if err != nil {
			return fmt.Errorf("error loading STHs: %w", err)
		}
		for len(sths) > 0 && sths[0].TreeSize < position {
			// TODO-4: audit sths[0] against log's verified STH
			if err := config.State.RemoveSTH(ctx, ctlog.LogID, &sths[0].SignedTreeHead); err != nil {
				return fmt.Errorf("error removing STH: %w", err)
			}
			sths = sths[1:]
		}
		position, number, err = generateBatches(ctx, ctlog, position, number, sths, batches)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return ctx.Err()
}

// return the time at which the right-most tile indicated by sths was discovered
func tileDiscoveryTime(sths []*StoredSTH) time.Time {
	largestSTH, sths := sths[len(sths)-1], sths[:len(sths)-1]
	tileNumber := largestSTH.TreeSize / ctclient.StaticTileWidth
	storedAt := largestSTH.StoredAt
	for _, sth := range slices.Backward(sths) {
		if sth.TreeSize/ctclient.StaticTileWidth != tileNumber {
			break
		}
		if sth.StoredAt.Before(storedAt) {
			storedAt = sth.StoredAt
		}
	}
	return storedAt
}

func generateBatches(ctx context.Context, ctlog *loglist.Log, position uint64, number uint64, sths []*StoredSTH, batches chan<- *batch) (uint64, uint64, error) {
	downloadJobSize := downloadJobSize(ctlog)
	if len(sths) == 0 {
		return position, number, nil
	}
	largestSTH := sths[len(sths)-1]
	treeSize := largestSTH.TreeSize
	if ctlog.IsStaticCTAPI() && time.Since(tileDiscoveryTime(sths)) < 5*time.Minute {
		// Round down to the tile boundary to avoid downloading a partial tile that was recently discovered
		// In a future invocation of this function, either enough time will have passed that this code path will be skipped, or the log will have grown and treeSize will be rounded to a larger tile boundary
		treeSize -= treeSize % ctclient.StaticTileWidth
	}
	for {
		batch := &batch{
			number: number,
			begin:  position,
			end:    min(treeSize, (position/downloadJobSize+1)*downloadJobSize),
		}
		for len(sths) > 0 && sths[0].TreeSize <= batch.end {
			batch.sths = append(batch.sths, sths[0])
			sths = sths[1:]
		}
		select {
		case <-ctx.Done():
			return position, number, ctx.Err()
		default:
		}
		select {
		case <-ctx.Done():
			return position, number, ctx.Err()
		case batches <- batch:
		}
		number++
		if position == batch.end {
			break
		}
		position = batch.end
	}
	return position, number, nil
}

func downloadWorker(ctx context.Context, config *Config, ctlog *loglist.Log, client ctclient.Log, batchesIn <-chan *batch, batchesOut chan<- *batch) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var batch *batch
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch = <-batchesIn:
		}

		entries, err := getEntriesFull(ctx, client, batch.begin, batch.end)
		if err != nil {
			return err
		}
		batch.entries = entries

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batchesOut <- batch:
		}
	}
	return nil
}

func processWorker(ctx context.Context, config *Config, ctlog *loglist.Log, issuerGetter ctclient.IssuerGetter, batchesIn <-chan *batch, batchesOut *sequencer.Channel[batch]) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var batch *batch
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch = <-batchesIn:
		}
		for offset, entry := range batch.entries {
			index := batch.begin + uint64(offset)
			if err := processLogEntry(ctx, config, issuerGetter, &LogEntry{
				Entry: entry,
				Index: index,
				Log:   ctlog,
			}); err != nil {
				return fmt.Errorf("error processing entry %d: %w", index, err)
			}
		}
		if err := batchesOut.Add(ctx, batch.number, batch); err != nil {
			return err
		}
	}
}

func saveStateWorker(ctx context.Context, config *Config, ctlog *loglist.Log, state *LogState, batchesIn *sequencer.Channel[batch]) error {
	for {
		batch, err := batchesIn.Next(ctx)
		if err != nil {
			return err
		}
		if batch.begin != state.DownloadPosition.Size() {
			panic(fmt.Errorf("saveStateWorker: expected batch to start at %d but got %d instead", state.DownloadPosition.Size(), batch.begin))
		}
		rootHash := state.DownloadPosition.CalculateRoot()
		for {
			for len(batch.sths) > 0 && batch.sths[0].TreeSize == state.DownloadPosition.Size() {
				sth := batch.sths[0]
				batch.sths = batch.sths[1:]
				if sth.RootHash != rootHash {
					return &verifyEntriesError{
						sth:             &sth.SignedTreeHead,
						entriesRootHash: rootHash,
					}
				}
				state.advanceVerifiedPosition()
				state.LastSuccess = sth.StoredAt
				state.VerifiedSTH = &sth.SignedTreeHead
				if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
					return fmt.Errorf("error storing log state: %w", err)
				}
				// don't remove the STH until state has been durably stored
				if err := config.State.RemoveSTH(ctx, ctlog.LogID, &sth.SignedTreeHead); err != nil {
					return fmt.Errorf("error removing verified STH: %w", err)
				}
			}
			if len(batch.entries) == 0 {
				break
			}
			entry := batch.entries[0]
			batch.entries = batch.entries[1:]
			leafHash := merkletree.HashLeaf(entry.LeafInput())
			state.DownloadPosition.Add(leafHash)
			rootHash = state.DownloadPosition.CalculateRoot()
		}

		if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
			return fmt.Errorf("error storing log state: %w", err)
		}
	}
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
