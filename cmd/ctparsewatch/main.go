// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"flag"
	"os"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/cmd"
	"software.sslmate.com/src/certspotter/ct"
)

func DefaultStateDir() string {
	if envVar := os.Getenv("CTPARSEWATCH_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("ctparsewatch")
	}
}

var stateDir = flag.String("state_dir", DefaultStateDir(), "Directory for storing state")

func processEntry(scanner *certspotter.Scanner, entry *ct.LogEntry) {
	info := certspotter.EntryInfo{
		LogUri:    scanner.LogUri,
		Entry:     entry,
		IsPrecert: certspotter.IsPrecert(entry),
		FullChain: certspotter.GetFullChain(entry),
	}

	info.CertInfo, info.ParseError = certspotter.MakeCertInfoFromLogEntry(entry)
	if info.CertInfo != nil {
		info.Identifiers, info.IdentifiersParseError = info.CertInfo.ParseIdentifiers()
	}

	if info.HasParseErrors() {
		cmd.LogEntry(&info)
	}
}

func main() {
	cmd.ParseFlags()
	os.Exit(cmd.Main(*stateDir, processEntry))
}
