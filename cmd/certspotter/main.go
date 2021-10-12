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
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/cmd"
	"software.sslmate.com/src/certspotter/ct"
)

func defaultStateDir() string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("certspotter")
	}
}
func defaultConfigDir() string {
	if envVar := os.Getenv("CERTSPOTTER_CONFIG_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultConfigDir("certspotter")
	}
}

func trimTrailingDots(value string) string {
	length := len(value)
	for length > 0 && value[length-1] == '.' {
		length--
	}
	return value[0:length]
}

var stateDir = flag.String("state_dir", defaultStateDir(), "Directory for storing state")
var watchlistFilename = flag.String("watchlist", filepath.Join(defaultConfigDir(), "watchlist"), "File containing identifiers to watch (- for stdin)")

type watchlistItem struct {
	Domain       []string
	AcceptSuffix bool
	ValidAt      *time.Time // optional
}

var watchlist []watchlistItem

func parseWatchlistItem(str string) (watchlistItem, error) {
	fields := strings.Fields(str)
	if len(fields) == 0 {
		return watchlistItem{}, fmt.Errorf("Empty domain")
	}
	domain := fields[0]
	var validAt *time.Time = nil

	// parse options
	for i := 1; i < len(fields); i++ {
		chunks := strings.SplitN(fields[i], ":", 2)
		if len(chunks) != 2 {
			return watchlistItem{}, fmt.Errorf("Missing Value `%s'", fields[i])
		}
		switch chunks[0] {
		case "valid_at":
			validAtTime, err := time.Parse("2006-01-02", chunks[1])
			if err != nil {
				return watchlistItem{}, fmt.Errorf("Invalid Date `%s': %s", chunks[1], err)
			}
			validAt = &validAtTime
		default:
			return watchlistItem{}, fmt.Errorf("Unknown Option `%s'", fields[i])
		}
	}

	// parse domain
	// "." as in root zone (matches everything)
	if domain == "." {
		return watchlistItem{
			Domain:       []string{},
			AcceptSuffix: true,
			ValidAt:      validAt,
		}, nil
	}

	acceptSuffix := false
	if strings.HasPrefix(domain, ".") {
		acceptSuffix = true
		domain = domain[1:]
	}

	asciiDomain, err := idna.ToASCII(strings.ToLower(trimTrailingDots(domain)))
	if err != nil {
		return watchlistItem{}, fmt.Errorf("Invalid domain `%s': %s", domain, err)
	}
	return watchlistItem{
		Domain:       strings.Split(asciiDomain, "."),
		AcceptSuffix: acceptSuffix,
		ValidAt:      validAt,
	}, nil
}

func readWatchlist(reader io.Reader) ([]watchlistItem, error) {
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

func dnsLabelMatches(certLabel string, watchLabel string) bool {
	// For fail-safe behavior, if a label was unparsable, it matches everything.
	// Similarly, redacted labels match everything, since the label _might_ be
	// for a name we're interested in.

	return certLabel == "*" ||
		certLabel == "?" ||
		certLabel == certspotter.UnparsableDNSLabelPlaceholder ||
		certspotter.MatchesWildcard(watchLabel, certLabel)
}

func dnsNameMatches(dnsName []string, watchDomain []string, acceptSuffix bool) bool {
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

func anyDnsNameIsWatched(info *certspotter.EntryInfo) bool {
	dnsNames := info.Identifiers.DNSNames
	matched := false
	for _, dnsName := range dnsNames {
		labels := strings.Split(dnsName, ".")
		for _, item := range watchlist {
			if dnsNameMatches(labels, item.Domain, item.AcceptSuffix) {
				if item.ValidAt != nil {
					// BygoneSSL Check
					// was the SSL certificate issued before the domain was registered
					// and valid after
					if item.ValidAt.Before(*info.CertInfo.NotAfter()) &&
						item.ValidAt.After(*info.CertInfo.NotBefore()) {
						info.Bygone = true
						return true
					}
				}
				// keep iterating in case another domain watched matches valid_at
				matched = true
			}
		}
	}
	return matched
}

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

	// Fail safe behavior: if info.Identifiers is nil (which is caused by a
	// parse error), report the certificate because we can't say for sure it
	// doesn't match a domain we care about.  We try very hard to make sure
	// parsing identifiers always succeeds, so false alarms should be rare.
	if info.Identifiers == nil || anyDnsNameIsWatched(&info) {
		cmd.LogEntry(&info)
	}
}

func main() {
	cmd.ParseFlags()

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
		watchlist, err = readWatchlist(file)
		file.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", os.Args[0], *watchlistFilename, err)
			os.Exit(1)
		}
	}

	os.Exit(cmd.Main(*stateDir, processEntry))
}
