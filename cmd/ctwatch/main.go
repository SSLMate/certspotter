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

	var domains []string
	if flag.NArg() == 1 && flag.Arg(0) == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error reading standard input: %s\n", os.Args[0], err)
			os.Exit(3)
		}
	} else {
		domains = flag.Args()
	}

	var matcher ctwatch.Matcher
	if len(domains) == 0 {
		matcher = ctwatch.MatchAll{}
	} else {
		matcher = ctwatch.NewDomainMatcher(domains)
	}

	cmd.Main(*stateDir, matcher)
}
