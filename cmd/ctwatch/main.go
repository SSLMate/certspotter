package main

import (
	"flag"
	"fmt"
	"os"
	"bufio"
	"strings"

	"src.agwa.name/ctwatch"
	"src.agwa.name/ctwatch/ct"
	"src.agwa.name/ctwatch/cmd"
)

func DefaultStateDir () string {
	if envVar := os.Getenv("CTWATCH_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("ctwatch")
	}
}

var stateDir = flag.String("state_dir", DefaultStateDir(), "Directory for storing state")
var watchDomains []string
var watchDomainSuffixes []string

func setWatchDomains (domains []string) {
	for _, domain := range domains {
		if domain == "." { // "." as in root zone (matches everything)
			watchDomains = []string{}
			watchDomainSuffixes = []string{""}
			break
		} else {
			watchDomains = append(watchDomains, strings.ToLower(domain))
			watchDomainSuffixes = append(watchDomainSuffixes, "." + strings.ToLower(domain))
		}
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
		IsPrecert:	ctwatch.IsPrecert(entry),
		FullChain:	ctwatch.GetFullChain(entry),
	}

	info.CertInfo, info.ParseError = ctwatch.MakeCertInfo(entry)

	if info.ParseError == nil && info.CertInfo.DNSNamesParseError == nil {
		// Match DNS names
		if !anyDnsNameMatches(info.CertInfo.DNSNames) {
			return
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
			os.Exit(1)
		}
		setWatchDomains(domains)
	} else {
		setWatchDomains(flag.Args())
	}

	cmd.Main(*stateDir, processEntry)
}
