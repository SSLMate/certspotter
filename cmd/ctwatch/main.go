package main

import (
	"flag"
	"fmt"
	"os"
	"bufio"
	"strings"

	"github.com/google/certificate-transparency/go"
	"src.agwa.name/ctwatch"
	"src.agwa.name/ctwatch/cmd"
)

var stateDir = flag.String("state_dir", cmd.DefaultStateDir("ctwatch"), "Directory for storing state")
var watchDomains []string
var watchDomainSuffixes []string

func setWatchDomains (domains []string) {
	for _, domain := range domains {
		watchDomains = append(watchDomains, strings.ToLower(domain))
		watchDomainSuffixes = append(watchDomainSuffixes, "." + strings.ToLower(domain))
	}
}

func dnsNameMatches (dnsName string) bool {
	dnsNameLower := strings.ToLower(dnsName)
	for _, domain := range watchDomains {
		if dnsNameLower == domain {
			return true
		}
	}
	for _, domainSuffix := range watchDomainSuffixes {
		if strings.HasSuffix(dnsNameLower, domainSuffix) {
			return true
		}
	}
	return false
}

func anyDnsNameMatches (dnsNames []string) bool {
	for _, dnsName := range dnsNames {
		if dnsNameMatches(dnsName) {
			return true
		}
	}
	return false
}

func processEntry (scanner *ctwatch.Scanner, entry *ct.LogEntry) {
	info := ctwatch.EntryInfo{
		LogUri:		scanner.LogUri,
		Entry:		entry,
	}

	// Extract DNS names
	var dnsNames []string
	dnsNames, info.ParseError = ctwatch.EntryDNSNames(entry)

	if info.ParseError == nil {
		// Match DNS names
		if !anyDnsNameMatches(dnsNames) {
			return
		}

		// Parse the certificate
		info.ParsedCert, info.ParseError = ctwatch.ParseEntryCertificate(entry)
		if info.ParsedCert != nil {
			info.CertInfo = ctwatch.MakeCertInfo(info.ParsedCert)
		} else {
			info.CertInfo.DnsNames = dnsNames
		}
	}

	cmd.LogEntry(&info)
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
			os.Exit(3)
		}
		setWatchDomains(domains)
	} else if flag.NArg() == 1 && flag.Arg(0) == "." { // "." as in root zone
		watchDomainSuffixes = []string{""}
	} else {
		setWatchDomains(flag.Args())
	}

	cmd.Main(*stateDir, processEntry)
}
