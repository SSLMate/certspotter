package main

import (
	"flag"
	"fmt"
	"os"
	"bufio"

	"src.agwa.name/ctwatch"
	"src.agwa.name/ctwatch/cmd"
)

func main() {
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] log_uri state_file [domain ...]\n", os.Args[0])
		os.Exit(2)
	}

	logUri := flag.Arg(0)
	stateFile := flag.Arg(1)

	var domains []string
	if flag.NArg() == 3 && flag.Arg(2) == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading standard input: %s\n", err)
			os.Exit(1)
		}
	} else {
		domains = flag.Args()[2:]
	}

	var matcher ctwatch.Matcher
	if len(domains) == 0 {
		matcher = ctwatch.MatchAll{}
	} else {
		matcher = ctwatch.NewDomainMatcher(domains)
	}

	cmd.Main(logUri, stateFile, matcher)
}
