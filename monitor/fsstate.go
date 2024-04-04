// Copyright (C) 2024 Opsmate, Inc.
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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/loglist"
)

type FilesystemState struct {
	StateDir  string
	SaveCerts bool
	Script    string
	ScriptDir string
	Email     []string
	Stdout    bool
}

func (s *FilesystemState) logStateDir(logID LogID) string {
	return filepath.Join(s.StateDir, "logs", logID.Base64URLString())
}

func (s *FilesystemState) Prepare(ctx context.Context) error {
	return prepareStateDir(s.StateDir)
}

func (s *FilesystemState) PrepareLog(ctx context.Context, logID LogID) error {
	var (
		stateDirPath        = s.logStateDir(logID)
		sthsDirPath         = filepath.Join(stateDirPath, "unverified_sths")
		malformedDirPath    = filepath.Join(stateDirPath, "malformed_entries")
		healthchecksDirPath = filepath.Join(stateDirPath, "healthchecks")
	)
	for _, dirPath := range []string{stateDirPath, sthsDirPath, malformedDirPath, healthchecksDirPath} {
		if err := os.Mkdir(dirPath, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

func (s *FilesystemState) LoadLogState(ctx context.Context, logID LogID) (*LogState, error) {
	filePath := filepath.Join(s.logStateDir(logID), "state.json")
	fileBytes, err := os.ReadFile(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	state := new(LogState)
	if err := json.Unmarshal(fileBytes, state); err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", filePath, err)
	}
	return state, nil
}

func (s *FilesystemState) StoreLogState(ctx context.Context, logID LogID, state *LogState) error {
	filePath := filepath.Join(s.logStateDir(logID), "state.json")
	return writeJSONFile(filePath, state, 0666)
}

func (s *FilesystemState) StoreSTH(ctx context.Context, logID LogID, sth *ct.SignedTreeHead) error {
	sthsDirPath := filepath.Join(s.logStateDir(logID), "unverified_sths")
	return storeSTHInDir(sthsDirPath, sth)
}

func (s *FilesystemState) LoadSTHs(ctx context.Context, logID LogID) ([]*ct.SignedTreeHead, error) {
	sthsDirPath := filepath.Join(s.logStateDir(logID), "unverified_sths")
	return loadSTHsFromDir(sthsDirPath)
}

func (s *FilesystemState) RemoveSTH(ctx context.Context, logID LogID, sth *ct.SignedTreeHead) error {
	sthsDirPath := filepath.Join(s.logStateDir(logID), "unverified_sths")
	return removeSTHFromDir(sthsDirPath, sth)
}

func (s *FilesystemState) NotifyCert(ctx context.Context, cert *DiscoveredCert) error {
	var notifiedPath string
	var paths *certPaths
	if s.SaveCerts {
		hexFingerprint := hex.EncodeToString(cert.SHA256[:])
		prefixPath := filepath.Join(s.StateDir, "certs", hexFingerprint[0:2])
		var (
			notifiedFilename      = "." + hexFingerprint + ".notified"
			certFilename          = hexFingerprint + ".pem"
			jsonFilename          = hexFingerprint + ".v1.json"
			textFilename          = hexFingerprint + ".txt"
			legacyCertFilename    = hexFingerprint + ".cert.pem"
			legacyPrecertFilename = hexFingerprint + ".precert.pem"
		)

		for _, filename := range []string{notifiedFilename, legacyCertFilename, legacyPrecertFilename} {
			if fileExists(filepath.Join(prefixPath, filename)) {
				return nil
			}
		}

		if err := os.Mkdir(prefixPath, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("error creating directory in which to save certificate %x: %w", cert.SHA256, err)
		}

		notifiedPath = filepath.Join(prefixPath, notifiedFilename)
		paths = &certPaths{
			certPath: filepath.Join(prefixPath, certFilename),
			jsonPath: filepath.Join(prefixPath, jsonFilename),
			textPath: filepath.Join(prefixPath, textFilename),
		}
		if err := writeCertFiles(cert, paths); err != nil {
			return fmt.Errorf("error saving certificate %x: %w", cert.SHA256, err)
		}
	} else {
		// TODO-4: save cert to temporary files, and defer their unlinking
	}

	if err := s.notify(ctx, &notification{
		summary: certNotificationSummary(cert),
		environ: certNotificationEnviron(cert, paths),
		text:    certNotificationText(cert, paths),
	}); err != nil {
		return fmt.Errorf("error notifying about discovered certificate for %s (%x): %w", cert.WatchItem, cert.SHA256, err)
	}

	if notifiedPath != "" {
		if err := os.WriteFile(notifiedPath, nil, 0666); err != nil {
			return fmt.Errorf("error saving certificate %x: %w", cert.SHA256, err)
		}
	}

	return nil
}

func (s *FilesystemState) NotifyMalformedEntry(ctx context.Context, entry *LogEntry, parseError error) error {
	var (
		dirPath   = filepath.Join(s.logStateDir(entry.Log.LogID), "malformed_entries")
		entryPath = filepath.Join(dirPath, fmt.Sprintf("%d.json", entry.Index))
		textPath  = filepath.Join(dirPath, fmt.Sprintf("%d.txt", entry.Index))
	)

	summary := fmt.Sprintf("Unable to Parse Entry %d in %s", entry.Index, entry.Log.URL)

	entryJSON := struct {
		LeafInput []byte `json:"leaf_input"`
		ExtraData []byte `json:"extra_data"`
	}{
		LeafInput: entry.LeafInput,
		ExtraData: entry.ExtraData,
	}

	text := new(strings.Builder)
	writeField := func(name string, value any) { fmt.Fprintf(text, "\t%13s = %s\n", name, value) }
	fmt.Fprintf(text, "Unable to determine if log entry matches your watchlist. Please file a bug report at https://github.com/SSLMate/certspotter/issues/new with the following details:\n")
	writeField("Log Entry", fmt.Sprintf("%d @ %s", entry.Index, entry.Log.URL))
	writeField("Leaf Hash", entry.LeafHash.Base64String())
	writeField("Error", parseError.Error())

	if err := writeJSONFile(entryPath, entryJSON, 0666); err != nil {
		return fmt.Errorf("error saving JSON file: %w", err)
	}
	if err := writeTextFile(textPath, text.String(), 0666); err != nil {
		return fmt.Errorf("error saving texT file: %w", err)
	}

	environ := []string{
		"EVENT=malformed_cert",
		"SUMMARY=" + summary,
		"LOG_URI=" + entry.Log.URL,
		"ENTRY_INDEX=" + fmt.Sprint(entry.Index),
		"LEAF_HASH=" + entry.LeafHash.Base64String(),
		"PARSE_ERROR=" + parseError.Error(),
		"ENTRY_FILENAME=" + entryPath,
		"TEXT_FILENAME=" + textPath,
		"CERT_PARSEABLE=no", // backwards compat with pre-0.15.0; not documented
	}

	if err := s.notify(ctx, &notification{
		environ: environ,
		summary: summary,
		text:    text.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (s *FilesystemState) healthCheckDir(ctlog *loglist.Log) string {
	if ctlog == nil {
		return filepath.Join(s.StateDir, "healthchecks")
	} else {
		return filepath.Join(s.logStateDir(ctlog.LogID), "healthchecks")
	}
}

func (s *FilesystemState) NotifyHealthCheckFailure(ctx context.Context, ctlog *loglist.Log, info HealthCheckFailure) error {
	textPath := filepath.Join(s.healthCheckDir(ctlog), healthCheckFilename())
	environ := []string{
		"EVENT=error",
		"SUMMARY=" + info.Summary(),
		"TEXT_FILENAME=" + textPath,
	}
	text := info.Text()
	if err := writeTextFile(textPath, text, 0666); err != nil {
		return fmt.Errorf("error saving text file: %w", err)
	}
	if err := s.notify(ctx, &notification{
		environ: environ,
		summary: info.Summary(),
		text:    text,
	}); err != nil {
		return err
	}
	return nil
}

func (s *FilesystemState) NotifyError(ctx context.Context, ctlog *loglist.Log, err error) error {
	if ctlog == nil {
		log.Print(err)
	} else {
		log.Print(ctlog.URL, ":", err)
	}
	return nil
}
