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
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"golang.org/x/crypto/cryptobyte"

	"software.sslmate.com/src/certspotter/merkletree"
	"software.sslmate.com/src/certspotter/cttypes"
)

const (
	staticTileHeight = 8
	StaticTileWidth  = 1 << staticTileHeight
)

func staticSubtreeSize(level uint64) uint64 { return 1 << (level * staticTileHeight) }

type StaticLog struct {
	SubmissionURL *url.URL
	MonitoringURL *url.URL
	ID            cttypes.LogID
	HTTPClient    *http.Client // nil to use default client
}

type StaticLogEntry struct {
	timestampedEntry []byte
	precertificate   []byte // nil iff x509 entry; non-nil iff precert entry
	chain            [][32]byte
}

func (ctlog *StaticLog) GetSTH(ctx context.Context) (*cttypes.SignedTreeHead, string, error) {
	fullURL := ctlog.MonitoringURL.JoinPath("/checkpoint").String()
	responseBody, err := get(ctx, ctlog.HTTPClient, fullURL)
	if err != nil {
		return nil, fullURL, err
	}
	sth, err := cttypes.ParseCheckpoint(responseBody, ctlog.ID)
	if err != nil {
		return nil, fullURL, err
	}
	return sth, fullURL, nil
}

func (ctlog *StaticLog) GetRoots(ctx context.Context) ([][]byte, error) {
	return getRoots(ctx, ctlog.HTTPClient, ctlog.SubmissionURL)
}

func (ctlog *StaticLog) getEntries(ctx context.Context, startInclusive uint64, endInclusive uint64) ([]StaticLogEntry, error) {
	var (
		tile       = startInclusive / StaticTileWidth
		skip       = startInclusive % StaticTileWidth
		tileWidth  = min(StaticTileWidth, endInclusive+1-tile*StaticTileWidth)
		numEntries = tileWidth - skip
	)

	data, err := ctlog.getDataTile(ctx, tile, tileWidth)
	if err != nil {
		return nil, err
	}
	var skippedEntry StaticLogEntry
	for i := range skip {
		if rest, err := skippedEntry.parse(data); err != nil {
			return nil, fmt.Errorf("error parsing skipped entry %d in tile %d: %w", i, tile, err)
		} else {
			data = rest
		}
	}
	entries := make([]StaticLogEntry, numEntries)
	for i := range numEntries {
		if rest, err := entries[i].parse(data); err != nil {
			return nil, fmt.Errorf("error parsing entry %d in tile %d: %w", skip+i, tile, err)
		} else {
			data = rest
		}
	}
	return entries, nil
}

func (ctlog *StaticLog) GetEntries(ctx context.Context, startInclusive uint64, endInclusive uint64) ([]Entry, error) {
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

func (ctlog *StaticLog) ReconstructTree(ctx context.Context, sth *cttypes.SignedTreeHead) (*merkletree.CollapsedTree, error) {
	type job struct {
		level  uint64
		offset uint64
		width  uint64
		tree   *merkletree.CollapsedTree
		err    error
	}
	var jobs []job
	for level, size := uint64(0), sth.TreeSize; size > 0; level++ {
		fullTiles := size / StaticTileWidth
		remainder := size % StaticTileWidth
		size = fullTiles
		if remainder > 0 {
			jobs = append(jobs, job{
				level:  level,
				offset: fullTiles,
				width:  remainder,
			})
		}
	}
	var wg sync.WaitGroup
	for i := range jobs {
		job := &jobs[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			job.tree, job.err = ctlog.getTileCollapsedTree(ctx, job.level, job.offset, job.width)
		}()
	}
	wg.Wait()

	var errs []error
	tree := new(merkletree.CollapsedTree)
	for i := range jobs {
		job := &jobs[len(jobs)-1-i]
		if job.err != nil {
			errs = append(errs, job.err)
			continue
		}
		if err := tree.Append(*job.tree); err != nil {
			panic(err)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	if rootHash := tree.CalculateRoot(); rootHash != sth.RootHash {
		return nil, fmt.Errorf("calculated root hash (%s) does not match STH (%s) at size %d", rootHash.Base64String(), sth.RootHash.Base64String(), sth.TreeSize)
	}

	return tree, nil
}

func (ctlog *StaticLog) getDataTile(ctx context.Context, tile uint64, width uint64) ([]byte, error) {
	if width == 0 || width > StaticTileWidth {
		panic("width is out of range")
	}
	var partialErr error
	if width < StaticTileWidth {
		fullURL := ctlog.MonitoringURL.JoinPath(formatTilePath("data", tile, width)).String()
		if data, err := get(ctx, ctlog.HTTPClient, fullURL); err != nil {
			partialErr = err
		} else {
			return data, nil
		}
	}

	fullURL := ctlog.MonitoringURL.JoinPath(formatTilePath("data", tile, 0)).String()
	if data, err := get(ctx, ctlog.HTTPClient, fullURL); err != nil {
		if partialErr != nil {
			return nil, partialErr
		} else {
			return nil, err
		}
	} else {
		return data, nil
	}
}

// returned slice is numHashes*merkletree.HashLen bytes long
func (ctlog *StaticLog) getTile(ctx context.Context, level uint64, tile uint64, numHashes uint64) ([]byte, error) {
	if numHashes == 0 || numHashes > StaticTileWidth {
		panic("numHashes is out of range")
	}

	var partialErr error
	if numHashes < StaticTileWidth {
		fullURL := ctlog.MonitoringURL.JoinPath(formatTilePath(strconv.FormatUint(level, 10), tile, numHashes)).String()
		if data, err := get(ctx, ctlog.HTTPClient, fullURL); err != nil {
			partialErr = err
		} else if expectedLen := merkletree.HashLen * int(numHashes); len(data) != expectedLen {
			return nil, fmt.Errorf("%s returned %d bytes instead of expected %d", fullURL, len(data), expectedLen)
		} else {
			return data, nil
		}
	}

	fullURL := ctlog.MonitoringURL.JoinPath(formatTilePath(strconv.FormatUint(level, 10), tile, 0)).String()
	if data, err := get(ctx, ctlog.HTTPClient, fullURL); err != nil {
		if partialErr != nil {
			return nil, partialErr
		} else {
			return nil, err
		}
	} else if expectedLen := merkletree.HashLen * StaticTileWidth; len(data) != expectedLen {
		return nil, fmt.Errorf("%s returned %d bytes instead of expected %d", fullURL, len(data), expectedLen)
	} else {
		desiredLen := merkletree.HashLen * int(numHashes)
		return data[:desiredLen], nil
	}
}

func (ctlog *StaticLog) getTileCollapsedTree(ctx context.Context, level uint64, tile uint64, numHashes uint64) (*merkletree.CollapsedTree, error) {
	data, err := ctlog.getTile(ctx, level, tile, numHashes)
	if err != nil {
		return nil, err
	}
	subtreeSize := staticSubtreeSize(level)
	offset := staticSubtreeSize(level+1) * tile

	tree := new(merkletree.CollapsedTree)
	if err := tree.InitSubtree(offset, nil, 0); err != nil {
		panic(err)
	}
	for i := uint64(0); i < numHashes; i++ {
		hash := (merkletree.Hash)(data[i*merkletree.HashLen : (i+1)*merkletree.HashLen])
		var subtree merkletree.CollapsedTree
		if err := subtree.InitSubtree(offset+i*subtreeSize, []merkletree.Hash{hash}, subtreeSize); err != nil {
			panic(err)
		}
		if err := tree.Append(subtree); err != nil {
			panic(err)
		}
	}
	return tree, nil
}

func (ctlog *StaticLog) GetIssuer(ctx context.Context, fingerprint *[32]byte) ([]byte, error) {
	fullURL := ctlog.MonitoringURL.JoinPath("/issuer/" + hex.EncodeToString(fingerprint[:])).String()
	data, err := get(ctx, ctlog.HTTPClient, fullURL)
	if err != nil {
		return nil, err
	}
	if gotFingerprint := sha256.Sum256(data); gotFingerprint != *fingerprint {
		return nil, fmt.Errorf("%s returned incorrect data with fingerprint %x", fullURL, gotFingerprint[:])
	}
	return data, nil
}

func (entry *StaticLogEntry) parse(input []byte) ([]byte, error) {
	var skipped cryptobyte.String
	str := cryptobyte.String(input)

	// TimestampedEntry.timestamp
	if !str.Skip(8) {
		return nil, fmt.Errorf("error reading timestamp")
	}
	// TimestampedEntry.entry_type
	var entryType uint16
	if !str.ReadUint16(&entryType) {
		return nil, fmt.Errorf("error reading entry type")
	}
	// TimestampedEntry.signed_entry
	if entryType == 0 {
		if !str.ReadUint24LengthPrefixed(&skipped) {
			return nil, fmt.Errorf("error reading certificate")
		}
	} else if entryType == 1 {
		if !str.Skip(32) {
			return nil, fmt.Errorf("error reading issuer_key_hash")
		}
		if !str.ReadUint24LengthPrefixed(&skipped) {
			return nil, fmt.Errorf("error reading tbs_certificate")
		}
	} else {
		return nil, fmt.Errorf("invalid entry type %d", entryType)
	}

	// TimestampedEntry.extensions
	if !str.ReadUint16LengthPrefixed(&skipped) {
		return nil, fmt.Errorf("error reading extensions")
	}

	timestampedEntryLen := len(input) - len(str)
	entry.timestampedEntry = input[:timestampedEntryLen]

	// precertificate
	if entryType == 1 {
		var precertificate cryptobyte.String
		if !str.ReadUint24LengthPrefixed(&precertificate) {
			return nil, fmt.Errorf("error reading precertificate")
		}
		entry.precertificate = precertificate
	} else {
		entry.precertificate = nil
	}

	// certificate_chain
	var chainBytes cryptobyte.String
	if !str.ReadUint16LengthPrefixed(&chainBytes) {
		return nil, fmt.Errorf("error reading certificate_chain")
	}
	entry.chain = make([][32]byte, 0, len(chainBytes)/32)
	for !chainBytes.Empty() {
		var fingerprint [32]byte
		if !chainBytes.CopyBytes(fingerprint[:]) {
			return nil, fmt.Errorf("error reading fingerprint in certificate_chain")
		}
		entry.chain = append(entry.chain, fingerprint)
	}

	return str, nil
}

func (entry *StaticLogEntry) LeafInput() []byte {
	return append([]byte{0, 0}, entry.timestampedEntry...)
}

func (entry *StaticLogEntry) ExtraData(ctx context.Context, issuerGetter IssuerGetter) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	if entry.precertificate != nil {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(entry.precertificate)
		})
	}
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, fingerprint := range entry.chain {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				cert, err := issuerGetter.GetIssuer(ctx, &fingerprint)
				if err != nil {
					panic(cryptobyte.BuildError{Err: fmt.Errorf("error getting issuer %x: %w", fingerprint, err)})
				}
				b.AddBytes(cert)
			})
		}
	})
	return b.Bytes()
}

func (entry *StaticLogEntry) Precertificate() (cttypes.ASN1Cert, error) {
	if entry.precertificate == nil {
		return nil, fmt.Errorf("not a precertificate entry")
	}
	return entry.precertificate, nil
}

func (entry *StaticLogEntry) ChainFingerprints() ([][32]byte, error) {
	return entry.chain, nil
}

func (entry *StaticLogEntry) GetChain(ctx context.Context, issuerGetter IssuerGetter) (cttypes.ASN1CertChain, error) {
	var (
		chain = make(cttypes.ASN1CertChain, len(entry.chain))
		errs  = make([]error, len(entry.chain))
	)
	var wg sync.WaitGroup
	for i, fingerprint := range entry.chain {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chain[i], errs[i] = issuerGetter.GetIssuer(ctx, &fingerprint)
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return chain, nil
}

func formatTilePath(level string, tile uint64, partial uint64) string {
	path := "tile/" + level + "/" + formatTileIndex(tile)
	if partial != 0 {
		path += fmt.Sprintf(".p/%d", partial)
	}
	return path
}

func formatTileIndex(tile uint64) string {
	const base = 1000
	str := fmt.Sprintf("%03d", tile%base)
	for tile >= base {
		tile = tile / base
		str = fmt.Sprintf("x%03d/%s", tile%base, str)
	}
	return str
}
