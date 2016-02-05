package main

import (
	"flag"
	"fmt"
	"os"
	"bufio"

	"src.agwa.name/ctwatch"
	"src.agwa.name/ctwatch/cmd"
)

var stateDir = flag.String("state_dir", cmd.DefaultStateDir("ctwatch"), "Directory for storing state")

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] domain ...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "To read domain list from stdin, use '-'. To monitor all domains, use '.'.\n")
		fmt.Fprintf(os.Stderr, "See '%s -help' for a list of valid flags.\n", os.Args[0])
		os.Exit(2)
	}

	var matcher ctwatch.Matcher
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
		matcher = ctwatch.NewDomainMatcher(domains)
	} else if flag.NArg() == 1 && flag.Arg(0) == "." { // "." as in root zone
		matcher = ctwatch.MatchAll{}
	} else {
		matcher = ctwatch.NewDomainMatcher(flag.Args())
	}

	cmd.Main(*stateDir, matcher)
}
