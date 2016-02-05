package cmd

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"src.agwa.name/ctwatch"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
)

var batchSize = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers")
var parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
var script = flag.String("script", "", "Script to execute when a matching certificate is found")
var repo = flag.String("repo", "", "Directory of scanned certificates")
var verbose = flag.Bool("verbose", false, "Be verbose")

var printMutex sync.Mutex

func logCallback (entry *ct.LogEntry) {
	if *repo != "" {
		alreadyPresent, err := ctwatch.WriteCertRepository(*repo, entry)
		if err != nil {
			log.Print(err)
		}
		if alreadyPresent {
			return
		}
	}

	if *script != "" {
		if err := ctwatch.InvokeHookScript(*script, entry); err != nil {
			log.Print(err)
		}
	} else {
		printMutex.Lock()
		ctwatch.DumpLogEntry(os.Stdout, entry)
		fmt.Fprintf(os.Stdout, "\n")
		printMutex.Unlock()
	}
}

func Main(logUri string, stateFile string, matcher ctwatch.Matcher) {
	startIndex, err := ctwatch.ReadStateFile(stateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Error reading state file: %s: %s\n", os.Args[0], stateFile, err)
		os.Exit(3)
	}

	os.Setenv("LOG_URI", logUri)

	logClient := client.New(logUri)
	opts := ctwatch.ScannerOptions{
		Matcher:       matcher,
		BatchSize:     *batchSize,
		NumWorkers:    *numWorkers,
		ParallelFetch: *parallelFetch,
		Quiet:         !*verbose,
	}
	scanner := ctwatch.NewScanner(logClient, opts)

	endIndex, err := scanner.TreeSize()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Error contacting log: %s: %s\n", os.Args[0], logUri, err)
		os.Exit(1)
	}

	if startIndex != -1 {
		if err := scanner.Scan(startIndex, endIndex, logCallback); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error scanning log: %s: %s\n", os.Args[0], logUri, err)
			os.Exit(1)
		}
	}

	if err := ctwatch.WriteStateFile(stateFile, endIndex); err != nil {
		fmt.Fprintf(os.Stderr, "%s: Error writing state file: %s: %s\n", os.Args[0], stateFile, err)
		os.Exit(3)
	}
}
