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
	"fmt"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/loglist"
)

func healthCheckFilename() string {
	return time.Now().UTC().Format(time.RFC3339) + ".txt"
}

func healthCheckLog(ctx context.Context, config *Config, ctlog *loglist.Log) error {
	state, err := config.State.LoadLogState(ctx, ctlog.LogID)
	if err != nil {
		return fmt.Errorf("error loading log state: %w", err)
	} else if state == nil {
		return nil
	}

	if time.Since(state.LastSuccess) < config.HealthCheckInterval {
		return nil
	}

	sths, err := config.State.LoadSTHs(ctx, ctlog.LogID)
	if err != nil {
		return fmt.Errorf("error loading STHs: %w", err)
	}

	if len(sths) == 0 {
		info := &StaleSTHInfo{
			log:         ctlog,
			LastSuccess: state.LastSuccess,
			LatestSTH:   state.VerifiedSTH,
		}
		if err := config.State.NotifyHealthCheckFailure(ctx, info); err != nil {
			return fmt.Errorf("error notifying about stale STH: %w", err)
		}
	} else {
		info := &BacklogInfo{
			log:       ctlog,
			LatestSTH: sths[len(sths)-1],
			Position:  state.DownloadPosition.Size(),
		}
		if err := config.State.NotifyHealthCheckFailure(ctx, info); err != nil {
			return fmt.Errorf("error notifying about backlog: %w", err)
		}
	}

	return nil
}

type HealthCheckFailure interface {
	Summary() string
	Text() string
	Log() *loglist.Log // returns nil if failure is not associated with a log
}

type StaleSTHInfo struct {
	log         *loglist.Log
	LastSuccess time.Time
	LatestSTH   *ct.SignedTreeHead // may be nil
}

type BacklogInfo struct {
	log       *loglist.Log
	LatestSTH *ct.SignedTreeHead
	Position  uint64
}

type StaleLogListInfo struct {
	Source        string
	LastSuccess   time.Time
	LastError     string
	LastErrorTime time.Time
}

func (e *BacklogInfo) Backlog() uint64 {
	return e.LatestSTH.TreeSize - e.Position
}

func (e *StaleSTHInfo) Log() *loglist.Log {
	return e.log
}
func (e *BacklogInfo) Log() *loglist.Log {
	return e.log
}
func (e *StaleLogListInfo) Log() *loglist.Log {
	return nil
}

func (e *StaleSTHInfo) Summary() string {
	return fmt.Sprintf("Unable to contact %s since %s", e.log.URL, e.LastSuccess)
}
func (e *BacklogInfo) Summary() string {
	return fmt.Sprintf("Backlog of size %d from %s", e.Backlog(), e.log.URL)
}
func (e *StaleLogListInfo) Summary() string {
	return fmt.Sprintf("Unable to retrieve log list since %s", e.LastSuccess)
}

func (e *StaleSTHInfo) Text() string {
	text := new(strings.Builder)
	fmt.Fprintf(text, "certspotter has been unable to contact %s since %s. Consequentially, certspotter may fail to notify you about certificates in this log.\n", e.log.URL, e.LastSuccess)
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
func (e *BacklogInfo) Text() string {
	text := new(strings.Builder)
	fmt.Fprintf(text, "certspotter has been unable to download entries from %s in a timely manner. Consequentially, certspotter may be slow to notify you about certificates in this log.\n", e.log.URL)
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "For more details, see certspotter's stderr output.\n")
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "Current log size = %d (as of %s)\n", e.LatestSTH.TreeSize, e.LatestSTH.TimestampTime())
	fmt.Fprintf(text, "Current position = %d\n", e.Position)
	fmt.Fprintf(text, "         Backlog = %d\n", e.Backlog())
	return text.String()
}
func (e *StaleLogListInfo) Text() string {
	text := new(strings.Builder)
	fmt.Fprintf(text, "certspotter has been unable to retrieve the log list from %s since %s.\n", e.Source, e.LastSuccess)
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "Last error (at %s): %s\n", e.LastErrorTime, e.LastError)
	fmt.Fprintf(text, "\n")
	fmt.Fprintf(text, "Consequentially, certspotter may not be monitoring all logs, and might fail to detect certificates.\n")
	return text.String()
}

// TODO-3: make the errors more actionable
