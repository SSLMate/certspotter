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
)

type malformedLogEntry struct {
	Entry *logEntry
	Error string
}

func (malformed *malformedLogEntry) Environ() []string {
	return []string{
		"EVENT=discovered_cert",
		"SUMMARY=" + fmt.Sprintf("unable to parse entry %d in %s", malformed.Entry.Index, malformed.Entry.Log.URL),
		"LOG_URI=" + malformed.Entry.Log.URL,
		"ENTRY_INDEX=" + fmt.Sprint(malformed.Entry.Index),
		"LEAF_HASH=" + malformed.Entry.LeafHash.Base64String(),
		"PARSE_ERROR=" + malformed.Error,
		"CERT_PARSEABLE=no", // backwards compat; not documented (TODO-3: consider removing)
	}
}

func (malformed *malformedLogEntry) Text() string {
	text := new(strings.Builder)
	writeField := func(name string, value any) { fmt.Fprintf(text, "\t%13s = %s\n", name, value) }

	fmt.Fprintf(text, "Unable to determine if log entry matches your watchlist. Please file a bug report at https://github.com/SSLMate/certspotter/issues/new with the following details:\n")
	writeField("Log Entry", fmt.Sprintf("%d @ %s", malformed.Entry.Index, malformed.Entry.Log.URL))
	writeField("Leaf Hash", malformed.Entry.LeafHash.Base64String())
	writeField("Error", malformed.Error)

	return text.String()
}

func (malformed *malformedLogEntry) EmailSubject() string {
	return fmt.Sprintf("[certspotter] Unable to Parse Entry %d in %s", malformed.Entry.Index, malformed.Entry.Log.URL)
}
