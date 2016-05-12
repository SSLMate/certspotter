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
	"bufio"
	"strings"

	"golang.org/x/net/idna"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/cmd"
)

func DefaultStateDir () string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("certspotter")
	}
}

func trimTrailingDots (value string) string {
	length := len(value)
	for length > 0 && value[length - 1] == '.' {
		length--
	}
	return value[0:length]
}

var stateDir = flag.String("state_dir", DefaultStateDir(), "Directory for storing state")
var watchDomains [][]string

func setWatchDomains (domains []string) error {
	for _, domain := range domains {
		if domain == "." { // "." as in root zone (matches everything)
			watchDomains = [][]string{[]string{}}
			break
		} else {
			asciiDomain, err := idna.ToASCII(strings.ToLower(trimTrailingDots(domain)))
			if err != nil {
				return fmt.Errorf("Invalid domain `%s': %s", domain, err)
			}

			watchDomains = append(watchDomains, strings.Split(asciiDomain, "."))
		}
	}
	return nil
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

func dnsNameMatches (dnsName []string, watchDomain []string) bool {
	for len(dnsName) > 0 && len(watchDomain) > 0 {
		certLabel := dnsName[len(dnsName)-1]
		watchLabel := watchDomain[len(watchDomain)-1]

		if !dnsLabelMatches(certLabel, watchLabel) {
			return false
		}

		dnsName = dnsName[:len(dnsName)-1]
		watchDomain = watchDomain[:len(watchDomain)-1]
	}

	return len(watchDomain) == 0
}

func dnsNameIsWatched (dnsName string) bool {
	labels := strings.Split(dnsName, ".")
	for _, watchDomain := range watchDomains {
		if dnsNameMatches(labels, watchDomain) {
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

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] domain ...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "To read domain list from stdin, use '-'. To monitor all domains, use '.'.\n")
		fmt.Fprintf(os.Stderr, "See '%s -help' for a list of valid flags.\n", os.Args[0])
		os.Exit(2)
	}

	if flag.NArg() == 1 && flag.Arg(0) == "-" {
		var domains []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error reading standard input: %s\n", os.Args[0], err)
			os.Exit(1)
		}
		if err := setWatchDomains(domains); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
			os.Exit(1)
		}
	} else {
		if err := setWatchDomains(flag.Args()); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
			os.Exit(1)
		}
	}

	cmd.Main(*stateDir, processEntry)
}
