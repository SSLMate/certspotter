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
	getSTHInterval    = 5 * time.Minute
	maxPartialTileAge = 5 * time.Minute
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

func withRetry(ctx context.Context, config *Config, ctlog *loglist.Log, maxRetries int, f func() error) error {
	minSleep := 1 * time.Second
	numRetries := 0
	for ctx.Err() == nil {
		err := f()
		if err == nil || errors.Is(err, context.Canceled) {
			return err
		}
		if maxRetries != -1 && numRetries >= maxRetries {
			return fmt.Errorf("%w (retried %d times)", err, numRetries)
		}
		recordError(ctx, config, ctlog, err)
		sleepTime := minSleep + mathrand.N(minSleep)
		if err := sleep(ctx, sleepTime); err != nil {
			return err
		}
		minSleep = min(minSleep*2, 5*time.Minute)
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
		return nil, "", err
	}
	if err := ctcrypto.PublicKey(ctlog.Key).Verify(ctcrypto.SignatureInputForSTH(sth), sth.Signature); err != nil {
		return nil, "", fmt.Errorf("STH has invalid signature: %w", err)
	}
	return sth, url, nil
}

type logClient struct {
	config *Config
	log    *loglist.Log
	client ctclient.Log
}

func (client *logClient) GetSTH(ctx context.Context) (sth *cttypes.SignedTreeHead, url string, err error) {
	err = withRetry(ctx, client.config, client.log, -1, func() error {
		sth, url, err = getAndVerifySTH(ctx, client.log, client.client)
		return err
	})
	return
}
func (client *logClient) GetRoots(ctx context.Context) (roots [][]byte, err error) {
	err = withRetry(ctx, client.config, client.log, -1, func() error {
		roots, err = client.client.GetRoots(ctx)
		return err
	})
	return
}
func (client *logClient) GetEntries(ctx context.Context, startInclusive, endInclusive uint64) (entries []ctclient.Entry, err error) {
	err = withRetry(ctx, client.config, client.log, -1, func() error {
		entries, err = client.client.GetEntries(ctx, startInclusive, endInclusive)
		return err
	})
	return
}
func (client *logClient) ReconstructTree(ctx context.Context, sth *cttypes.SignedTreeHead) (tree *merkletree.CollapsedTree, err error) {
	err = withRetry(ctx, client.config, client.log, -1, func() error {
		tree, err = client.client.ReconstructTree(ctx, sth)
		return err
	})
	return
}

type issuerGetter struct {
	config    *Config
	log       *loglist.Log
	logGetter ctclient.IssuerGetter
}

func (ig *issuerGetter) GetIssuer(ctx context.Context, fingerprint *[32]byte) ([]byte, error) {
	if issuer, err := ig.config.State.LoadIssuer(ctx, fingerprint); err != nil {
		log.Printf("error loading cached issuer %x (issuer will be retrieved from log instead): %s", *fingerprint, err)
	} else if issuer != nil {
		return issuer, nil
	}

	var issuer []byte
	if err := withRetry(ctx, ig.config, ig.log, 7, func() error {
		var err error
		issuer, err = ig.logGetter.GetIssuer(ctx, fingerprint)
		return err
	}); err != nil {
		return nil, err
	}

	if err := ig.config.State.StoreIssuer(ctx, fingerprint, issuer); err != nil {
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
			config: config,
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
				config: config,
				log:    ctlog,
				client: client,
			}, &issuerGetter{
				config:    config,
				log:       ctlog,
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
			log.Printf("%s: monitoring brand new log starting from position %d", ctlog.GetMonitoringURL(), state.DownloadPosition.Size())
		}
		if err := config.State.StoreLogState(ctx, ctlog.LogID, state); err != nil {
			return fmt.Errorf("error storing log state: %w", err)
		}
	} else {
		if config.Verbose {
			log.Printf("%s: resuming monitoring from position %d", ctlog.GetMonitoringURL(), state.DownloadPosition.Size())
		}
	}

	defer func() {
		storeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := config.State.StoreLogState(storeCtx, ctlog.LogID, state); err != nil && returnedErr == nil {
			returnedErr = fmt.Errorf("error storing log state: %w", err)
		}
	}()

retry:
	position := state.DownloadPosition.Size()

	// logs are monitored using the following pipeline of workers, with each worker sending results to the next worker:
	//     1 getSTHWorker ==> 1 generateBatchesWorker ==> multiple downloadWorkers ==> multiple processWorkers ==> 1 saveStateWorker
	// getSTHWorker          - periodically download STHs from the log
	// generateBatchesWorker - generate batches of work
	// downloadWorkers       - download the entries in each batch
	// processWorkers        - process the certificates (store/notify if matches watch list) in each batch
	// saveStateWorker       - builds the Merkle Tree and compares against STHs

	sths := make(chan *cttypes.SignedTreeHead, 1)
	batches := make(chan *batch, downloadWorkers(ctlog))
	processedBatches := sequencer.New[batch](0, uint64(downloadWorkers(ctlog))*10)

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return getSTHWorker(gctx, config, ctlog, client, sths) })
	group.Go(func() error { return generateBatchesWorker(gctx, config, ctlog, position, sths, batches) })
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

func getSTHWorker(ctx context.Context, config *Config, ctlog *loglist.Log, client ctclient.Log, sthsOut chan<- *cttypes.SignedTreeHead) error {
	ticker := time.NewTicker(getSTHInterval)
	defer ticker.Stop()
	for {
		sth, _, err := client.GetSTH(ctx)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sthsOut <- sth:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type batch struct {
	number       uint64
	begin, end   uint64
	discoveredAt time.Time        // time at which we became aware of the log having entries in range [begin,end)
	sths         []*StoredSTH     // STHs with sizes in range [begin,end], sorted by TreeSize
	entries      []ctclient.Entry // in range [begin,end)
}

// Create a batch starting from begin, based on sths (which must be non-empty, sorted by TreeSize, and contain only STHs with TreeSize >= begin).  Returns the batch, plus the remaining STHs.
func newBatch(number uint64, begin uint64, sths []*StoredSTH, downloadJobSize uint64) (*batch, []*StoredSTH) {
	batch := &batch{
		number:       number,
		begin:        begin,
		discoveredAt: sths[0].StoredAt,
	}
	maxEnd := (begin/downloadJobSize + 1) * downloadJobSize
	for _, sth := range sths {
		if sth.StoredAt.Before(batch.discoveredAt) {
			batch.discoveredAt = sth.StoredAt
		}
		if sth.TreeSize <= maxEnd {
			batch.end = sth.TreeSize
			batch.sths = append(batch.sths, sth)
		} else {
			batch.end = maxEnd
			break
		}
	}
	return batch, sths[len(batch.sths):]
}

// insert sth into sths, which is sorted by TreeSize, and return a new, still-sorted slice.
// if an equivalent STH is already in sths, it is returned unchanged.
func insertSTH(sths []*StoredSTH, sth *StoredSTH) []*StoredSTH {
	i := len(sths)
	for i > 0 {
		if sths[i-1].Same(&sth.SignedTreeHead) {
			return sths
		}
		if sths[i-1].TreeSize < sth.TreeSize {
			break
		}
		i--
	}
	return slices.Insert(sths, i, sth)
}

func generateBatchesWorker(ctx context.Context, config *Config, ctlog *loglist.Log, position uint64, sthsIn <-chan *cttypes.SignedTreeHead, batchesOut chan<- *batch) error {
	downloadJobSize := downloadJobSize(ctlog)

	sths, err := config.State.LoadSTHs(ctx, ctlog.LogID)
	if err != nil {
		return fmt.Errorf("error loading STHs: %w", err)
	}
	// sths is sorted by TreeSize but may contain STHs with TreeSize < position; get rid of them
	for len(sths) > 0 && sths[0].TreeSize < position {
		// TODO-4: audit sths[0] against log's verified STH
		if err := config.State.RemoveSTH(ctx, ctlog.LogID, &sths[0].SignedTreeHead); err != nil {
			return fmt.Errorf("error removing STH: %w", err)
		}
		sths = sths[1:]
	}
	// from this point, sths is sorted by TreeSize and contains only STHs with TreeSize >= position
	handleSTH := func(sth *cttypes.SignedTreeHead) error {
		if sth.TreeSize < position {
			// TODO-4: audit against log's verified STH
		} else {
			storedSTH, err := config.State.StoreSTH(ctx, ctlog.LogID, sth)
			if err != nil {
				return fmt.Errorf("error storing STH: %w", err)
			}
			sths = insertSTH(sths, storedSTH)
		}
		return nil
	}

	var number uint64
	for {
		for len(sths) == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case sth := <-sthsIn:
				if err := handleSTH(sth); err != nil {
					return err
				}
			}
		}

		batch, remainingSTHs := newBatch(number, position, sths, downloadJobSize)

		if ctlog.IsStaticCTAPI() && batch.end%downloadJobSize != 0 {
			// Wait to download this partial tile until it's old enough
			if age := time.Since(batch.discoveredAt); age < maxPartialTileAge {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(maxPartialTileAge - age):
				case sth := <-sthsIn:
					if err := handleSTH(sth); err != nil {
						return err
					}
					continue
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case sth := <-sthsIn:
			if err := handleSTH(sth); err != nil {
				return err
			}
		case batchesOut <- batch:
			number = batch.number + 1
			position = batch.end
			sths = remainingSTHs
		}
	}
}

func downloadWorker(ctx context.Context, config *Config, ctlog *loglist.Log, client ctclient.Log, batchesIn <-chan *batch, batchesOut chan<- *batch) error {
	for {
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
		case batchesOut <- batch:
		}
	}
}

func processWorker(ctx context.Context, config *Config, ctlog *loglist.Log, issuerGetter ctclient.IssuerGetter, batchesIn <-chan *batch, batchesOut *sequencer.Channel[batch]) error {
	for {
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
		for {
			for len(batch.sths) > 0 && batch.sths[0].TreeSize == state.DownloadPosition.Size() {
				sth := batch.sths[0]
				batch.sths = batch.sths[1:]
				if rootHash := state.DownloadPosition.CalculateRoot(); sth.RootHash != rootHash {
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
				if config.Verbose {
					log.Printf("%s: verified position is now %d", ctlog.GetMonitoringURL(), sth.SignedTreeHead.TreeSize)
				}
			}
			if len(batch.entries) == 0 {
				break
			}
			entry := batch.entries[0]
			batch.entries = batch.entries[1:]
			leafHash := merkletree.HashLeaf(entry.LeafInput())
			state.DownloadPosition.Add(leafHash)
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
