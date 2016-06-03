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
	"fmt"
	"os"
	"io"
	"bufio"
	"strings"
	"path/filepath"

	"golang.org/x/net/idna"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/cmd"
)

func defaultStateDir () string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("certspotter")
	}
}
func defaultConfigDir () string {
	if envVar := os.Getenv("CERTSPOTTER_CONFIG_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultConfigDir("certspotter")
	}
}

func trimTrailingDots (value string) string {
	length := len(value)
	for length > 0 && value[length - 1] == '.' {
		length--
	}
	return value[0:length]
}

var stateDir = flag.String("state_dir", defaultStateDir(), "Directory for storing state")
var watchlistFilename = flag.String("watchlist", filepath.Join(defaultConfigDir(), "watchlist"), "File containing identifiers to watch (- for stdin)")

type watchlistItem struct {
	Domain		[]string
	AcceptSuffix	bool
}
var watchlist []watchlistItem

func parseWatchlistItem (str string) (watchlistItem, error) {
	if str == "." { // "." as in root zone (matches everything)
		return watchlistItem{
			Domain: []string{},
			AcceptSuffix: true,
		}, nil
	} else {
		acceptSuffix := false
		if strings.HasPrefix(str, ".") {
			acceptSuffix = true
			str = str[1:]
		}
		asciiDomain, err := idna.ToASCII(strings.ToLower(trimTrailingDots(str)))
		if err != nil {
			return watchlistItem{}, fmt.Errorf("Invalid domain `%s': %s", str, err)
		}
		return watchlistItem{
			Domain: strings.Split(asciiDomain, "."),
			AcceptSuffix: acceptSuffix,
		}, nil
	}
}

func readWatchlist (reader io.Reader) ([]watchlistItem, error) {
	items := []watchlistItem{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		item, err := parseWatchlistItem(line)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}

func dnsLabelMatches (certLabel string, watchLabel string) bool {
	// For fail-safe behavior, if a label was unparsable, it matches everything.
	// Similarly, redacted labels match everything, since the label _might_ be
	// for a name we're interested in.

	return certLabel == "*" ||
	       certLabel == "?" ||
	       certLabel == certspotter.UnparsableDNSLabelPlaceholder ||
	       certspotter.MatchesWildcard(watchLabel, certLabel)
}

func dnsNameMatches (dnsName []string, watchDomain []string, acceptSuffix bool) bool {
	for len(dnsName) > 0 && len(watchDomain) > 0 {
		certLabel := dnsName[len(dnsName)-1]
		watchLabel := watchDomain[len(watchDomain)-1]

		if !dnsLabelMatches(certLabel, watchLabel) {
			return false
		}

		dnsName = dnsName[:len(dnsName)-1]
		watchDomain = watchDomain[:len(watchDomain)-1]
	}

	return len(watchDomain) == 0 && (acceptSuffix || len(dnsName) == 0)
}

func dnsNameIsWatched (dnsName string) bool {
	labels := strings.Split(dnsName, ".")
	for _, item := range watchlist {
		if dnsNameMatches(labels, item.Domain, item.AcceptSuffix) {
			return true
		}
	}
	return false
}

func anyDnsNameIsWatched (dnsNames []string) bool {
	for _, dnsName := range dnsNames {
		if dnsNameIsWatched(dnsName) {
			return true
		}
	}
	return false
}

func processEntry (scanner *certspotter.Scanner, entry *ct.LogEntry) {
	info := certspotter.EntryInfo{
		LogUri:		scanner.LogUri,
		Entry:		entry,
		IsPrecert:	certspotter.IsPrecert(entry),
		FullChain:	certspotter.GetFullChain(entry),
	}

	info.CertInfo, info.ParseError = certspotter.MakeCertInfoFromLogEntry(entry)

	if info.CertInfo != nil {
		info.Identifiers, info.IdentifiersParseError = info.CertInfo.ParseIdentifiers()
	}

	// Fail safe behavior: if info.Identifiers is nil (which is caused by a
	// parse error), report the certificate because we can't say for sure it
	// doesn't match a domain we care about.  We try very hard to make sure
	// parsing identifiers always succeeds, so false alarms should be rare.
	if info.Identifiers == nil || anyDnsNameIsWatched(info.Identifiers.DNSNames) {
		cmd.LogEntry(&info)
	}
}

func main() {
	flag.Parse()

	if *watchlistFilename == "-" {
		var err error
		watchlist, err = readWatchlist(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: (stdin): %s\n", os.Args[0], err)
			os.Exit(1)
		}
	} else {
		file, err := os.Open(*watchlistFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", os.Args[0], *watchlistFilename, err)
			os.Exit(1)
		}
		defer file.Close()
		watchlist, err = readWatchlist(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", os.Args[0], *watchlistFilename, err)
			os.Exit(1)
		}
	}

	os.Exit(cmd.Main(*stateDir, processEntry))
}
