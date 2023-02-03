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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/certspotter/merkletree"
)

type logEntry struct {
	Log       *loglist.Log
	Index     uint64
	LeafInput []byte
	ExtraData []byte
	LeafHash  merkletree.Hash
}

func processLogEntry(ctx context.Context, config *Config, entry *logEntry) error {
	leaf, err := ct.ReadMerkleTreeLeaf(bytes.NewReader(entry.LeafInput))
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing Merkle Tree Leaf: %w", err))
	}
	switch leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		return processX509LogEntry(ctx, config, entry, leaf.TimestampedEntry.X509Entry)
	case ct.PrecertLogEntryType:
		return processPrecertLogEntry(ctx, config, entry, leaf.TimestampedEntry.PrecertEntry)
	default:
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("unknown log entry type %d", leaf.TimestampedEntry.EntryType))
	}
}

func processX509LogEntry(ctx context.Context, config *Config, entry *logEntry, cert ct.ASN1Cert) error {
	certInfo, err := certspotter.MakeCertInfoFromRawCert(cert)
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing X.509 certificate: %w", err))
	}

	chain, err := ct.UnmarshalX509ChainArray(entry.ExtraData)
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing extra_data for X.509 entry: %w", err))
	}
	chain = append([]ct.ASN1Cert{cert}, chain...)

	return processCertificate(ctx, config, entry, certInfo, chain)
}

func processPrecertLogEntry(ctx context.Context, config *Config, entry *logEntry, precert ct.PreCert) error {
	certInfo, err := certspotter.MakeCertInfoFromRawTBS(precert.TBSCertificate)
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing precert TBSCertificate: %w", err))
	}

	chain, err := ct.UnmarshalPrecertChainArray(entry.ExtraData)
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, fmt.Errorf("error parsing extra_data for precert entry: %w", err))
	}

	return processCertificate(ctx, config, entry, certInfo, chain)
}

func processCertificate(ctx context.Context, config *Config, entry *logEntry, certInfo *certspotter.CertInfo, chain []ct.ASN1Cert) error {
	identifiers, err := certInfo.ParseIdentifiers()
	if err != nil {
		return processMalformedLogEntry(ctx, config, entry, err)
	}
	matched, watchItem := config.WatchList.Matches(identifiers)
	if !matched {
		return nil
	}

	cert := &discoveredCert{
		WatchItem:   watchItem,
		LogEntry:    entry,
		Info:        certInfo,
		Chain:       chain,
		LeafSHA256:  sha256.Sum256(chain[0]),
		Identifiers: identifiers,
	}

	var notifiedPath string
	if config.SaveCerts {
		hexFingerprint := hex.EncodeToString(cert.LeafSHA256[:])
		prefixPath := filepath.Join(config.StateDir, "certs", hexFingerprint[0:2])

		for _, suffix := range []string{".notified", ".cert.pem", ".precert.pem"} {
			if fileExists(filepath.Join(prefixPath, hexFingerprint+suffix)) {
				return nil
			}
		}

		if err := os.Mkdir(prefixPath, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("error creating directory in which to save certificate %x: %w", cert.LeafSHA256, err)
		}

		notifiedPath = filepath.Join(prefixPath, hexFingerprint+".notified") // TODO-3: maybe this should be a hidden file?
		cert.CertPath = filepath.Join(prefixPath, hexFingerprint+".pem")
		cert.JSONPath = filepath.Join(prefixPath, hexFingerprint+".json") // TODO-3: consider using .v1.json extension in case I change the format later?
		cert.TextPath = filepath.Join(prefixPath, hexFingerprint+".txt")

		if err := cert.save(); err != nil {
			return fmt.Errorf("error saving certificate %x: %w", cert.LeafSHA256, err)
		}
	} else {
		// TODO-4: save cert to temporary files, and defer their unlinking
	}

	if err := notify(ctx, config, cert); err != nil {
		return fmt.Errorf("error notifying about discovered certificate for %s (%x): %w", cert.WatchItem, cert.LeafSHA256, err)
	}

	if notifiedPath != "" {
		if err := os.WriteFile(notifiedPath, nil, 0666); err != nil {
			return fmt.Errorf("error saving certificate %x: %w", cert.LeafSHA256, err)
		}
	}

	return nil
}

func processMalformedLogEntry(ctx context.Context, config *Config, entry *logEntry, parseError error) error {
	// TODO-4: save the malformed entry (in get-entries format) in the state directory so user can inspect it

	malformed := &malformedLogEntry{
		Entry: entry,
		Error: parseError.Error(),
	}
	if err := notify(ctx, config, malformed); err != nil {
		return fmt.Errorf("error notifying about malformed log entry %d in %s (%q): %w", entry.Index, entry.Log.URL, parseError, err)
	}
	return nil
}
