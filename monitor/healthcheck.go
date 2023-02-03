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
	"fmt"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/loglist"
)

type staleSTHEvent struct {
	Log         *loglist.Log
	LastSuccess time.Time
	LatestSTH   *ct.SignedTreeHead // may be nil
}
type backlogEvent struct {
	Log       *loglist.Log
	LatestSTH *ct.SignedTreeHead
	Backlog   uint64
	Position  uint64
}
type staleLogListEvent struct {
	Source        string
	LastSuccess   time.Time
	LastError     string
	LastErrorTime time.Time
}

func (e *staleSTHEvent) Environ() []string {
	return []string{
		"EVENT=error",
		"SUMMARY=" + fmt.Sprintf("unable to contact %s since %s", e.Log.URL, e.LastSuccess),
	}
}
func (e *backlogEvent) Environ() []string {
	return []string{
		"EVENT=error",
		"SUMMARY=" + fmt.Sprintf("backlog of size %d from %s", e.Backlog, e.Log.URL),
	}
}
func (e *staleLogListEvent) Environ() []string {
	return []string{
		"EVENT=error",
		"SUMMARY=" + fmt.Sprintf("unable to retrieve log list since %s: %s", e.LastSuccess, e.LastError),
	}
}

func (e *staleSTHEvent) EmailSubject() string {
	return fmt.Sprintf("[certspotter] Unable to contact %s since %s", e.Log.URL, e.LastSuccess)
}
func (e *backlogEvent) EmailSubject() string {
	return fmt.Sprintf("[certspotter] Backlog of size %d from %s", e.Backlog, e.Log.URL)
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
		fmt.Fprintf(text, "Latest known log size = %d (as of %s)\n", e.LatestSTH.TreeSize, e.LatestSTH.Timestamp)
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
	fmt.Fprintf(text, "Current log size = %d (as of %s)\n", e.LatestSTH.TreeSize, e.LatestSTH.Timestamp)
	fmt.Fprintf(text, "Current position = %d\n", e.Position)
	fmt.Fprintf(text, "         Backlog = %d\n", e.Backlog)
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

// TODO-3: make the errors more actionable
