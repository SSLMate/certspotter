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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/loglist"
)

func healthCheckFilename() string {
	return time.Now().UTC().Format(time.RFC3339) + ".txt"
}

func healthCheckLog(ctx context.Context, config *Config, ctlog *loglist.Log) error {
	var (
		stateDirPath  = filepath.Join(config.StateDir, "logs", ctlog.LogID.Base64URLString())
		stateFilePath = filepath.Join(stateDirPath, "state.json")
		sthsDirPath   = filepath.Join(stateDirPath, "unverified_sths")
		textPath      = filepath.Join(stateDirPath, "healthchecks", healthCheckFilename())
	)
	state, err := loadStateFile(stateFilePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("error loading state file: %w", err)
	}

	if time.Since(state.LastSuccess) < config.HealthCheckInterval {
		return nil
	}

	sths, err := loadSTHsFromDir(sthsDirPath)
	if err != nil {
		return fmt.Errorf("error loading STHs directory: %w", err)
	}

	if len(sths) == 0 {
		event := &staleSTHEvent{
			Log:         ctlog,
			LastSuccess: state.LastSuccess,
			LatestSTH:   state.VerifiedSTH,
			TextPath:    textPath,
		}
		if err := event.save(); err != nil {
			return fmt.Errorf("error saving stale STH event: %w", err)
		}
		if err := notify(ctx, config, event); err != nil {
			return fmt.Errorf("error notifying about stale STH: %w", err)
		}
	} else {
		event := &backlogEvent{
			Log:       ctlog,
			LatestSTH: sths[len(sths)-1],
			Position:  state.DownloadPosition.Size(),
			TextPath:  textPath,
		}
		if err := event.save(); err != nil {
			return fmt.Errorf("error saving backlog event: %w", err)
		}
		if err := notify(ctx, config, event); err != nil {
			return fmt.Errorf("error notifying about backlog: %w", err)
		}
	}

	return nil
}

type staleSTHEvent struct {
	Log         *loglist.Log
	LastSuccess time.Time
	LatestSTH   *ct.SignedTreeHead // may be nil
	TextPath    string
}
type backlogEvent struct {
	Log       *loglist.Log
	LatestSTH *ct.SignedTreeHead
	Position  uint64
	TextPath  string
}
type staleLogListEvent struct {
	Source        string
	LastSuccess   time.Time
	LastError     string
	LastErrorTime time.Time
	TextPath      string
}

func (e *backlogEvent) Backlog() uint64 {
	return e.LatestSTH.TreeSize - e.Position
}

func (e *staleSTHEvent) Environ() []string {
	return []string{
		"EVENT=error",
		"TEXT_FILENAME=" + e.TextPath,
		"SUMMARY=" + fmt.Sprintf("unable to contact %s since %s", e.Log.URL, e.LastSuccess),
	}
}
func (e *backlogEvent) Environ() []string {
	return []string{
		"EVENT=error",
		"TEXT_FILENAME=" + e.TextPath,
		"SUMMARY=" + fmt.Sprintf("backlog of size %d from %s", e.Backlog(), e.Log.URL),
	}
}
func (e *staleLogListEvent) Environ() []string {
	return []string{
		"EVENT=error",
		"TEXT_FILENAME=" + e.TextPath,
		"SUMMARY=" + fmt.Sprintf("unable to retrieve log list since %s: %s", e.LastSuccess, e.LastError),
	}
}

func (e *staleSTHEvent) EmailSubject() string {
	return fmt.Sprintf("[certspotter] Unable to contact %s since %s", e.Log.URL, e.LastSuccess)
}
func (e *backlogEvent) EmailSubject() string {
	return fmt.Sprintf("[certspotter] Backlog of size %d from %s", e.Backlog(), e.Log.URL)
}
func (e *staleLogListEvent) EmailSubject() string {
	return fmt.Sprintf("[certspotter] Unable to retrieve log list since %s", e.LastSuccess)
}

func (e *staleSTHEvent) Text() string {
	text := new(strings.Builder)
	fmt.Fprintf(text, "certspotter has been unable to contact %s since %s. Consequentially, certspotter may fail to notify you about certificates in this log.\n", e.Log.URL, e.LastSuccess)
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "For details, see certspotter's stderr output.\n")
	fmt.Fprintf(text, "\n")
	if e.LatestSTH != nil {
		fmt.Fprintf(text, "Latest known log size = %d (as of %s)\n", e.LatestSTH.TreeSize, e.LatestSTH.TimestampTime())
	} else {
		fmt.Fprintf(text, "Latest known log size = none\n")
	}
	return text.String()
}
func (e *backlogEvent) Text() string {
	text := new(strings.Builder)
	fmt.Fprintf(text, "certspotter has been unable to download entries from %s in a timely manner. Consequentially, certspotter may be slow to notify you about certificates in this log.\n", e.Log.URL)
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "For more details, see certspotter's stderr output.\n")
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "Current log size = %d (as of %s)\n", e.LatestSTH.TreeSize, e.LatestSTH.TimestampTime())
	fmt.Fprintf(text, "Current position = %d\n", e.Position)
	fmt.Fprintf(text, "         Backlog = %d\n", e.Backlog())
	return text.String()
}
func (e *staleLogListEvent) Text() string {
	text := new(strings.Builder)
	fmt.Fprintf(text, "certspotter has been unable to retrieve the log list from %s since %s.\n", e.Source, e.LastSuccess)
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "Last error (at %s): %s\n", e.LastErrorTime, e.LastError)
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "Consequentially, certspotter may not be monitoring all logs, and might fail to detect certificates.\n")
	return text.String()
}

func (e *staleSTHEvent) save() error {
	return writeTextFile(e.TextPath, e.Text(), 0666)
}
func (e *backlogEvent) save() error {
	return writeTextFile(e.TextPath, e.Text(), 0666)
}
func (e *staleLogListEvent) save() error {
	return writeTextFile(e.TextPath, e.Text(), 0666)
}

// TODO-3: make the errors more actionable
