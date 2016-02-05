package cmd

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"bufio"
	"sync"
	"strings"
	"path/filepath"

	"src.agwa.name/ctwatch"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
)

var batchSize = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers")
var parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
var script = flag.String("script", "", "Script to execute when a matching certificate is found")
var logsFilename = flag.String("logs", "", "File containing log URLs")
var noSave = flag.Bool("no_save", false, "Do not save a copy of matching certificates")
var verbose = flag.Bool("verbose", false, "Be verbose")
var stateDir string

var printMutex sync.Mutex

var defaultLogs = []string{
	"https://log.certly.io",
	"https://ct1.digicert-ct.com/log",
	"https://ct.googleapis.com/aviator",
	"https://ct.googleapis.com/pilot",
	"https://ct.googleapis.com/rocketeer",
	"https://ct.izenpe.com",
	"https://ct.ws.symantec.com",
	"https://vega.ws.symantec.com",
	"https://ctlog.api.venafi.com",
	"https://ct.wosign.com",
}

func isRoot () bool {
	return os.Geteuid() == 0
}

func homedir () string {
	home := os.Getenv("HOME")
	if home != "" {
		return home
	}
	user, err := user.Current()
	if err == nil {
		return user.HomeDir
	}
	panic("Unable to determine home directory")
}

func DefaultStateDir (programName string) string {
	if isRoot() {
		return filepath.Join("/var/lib", programName)
	} else {
		return filepath.Join(homedir(), "." + programName)
	}
}

func logCallback (scanner *ctwatch.Scanner, entry *ct.LogEntry) {
	if !*noSave {
		alreadyPresent, err := ctwatch.WriteCertRepository(filepath.Join(stateDir, "certs"), entry)
		if err != nil {
			log.Print(err)
		}
		if alreadyPresent {
			return
		}
	}

	if *script != "" {
		if err := ctwatch.InvokeHookScript(*script, scanner.LogUri, entry); err != nil {
			log.Print(err)
		}
	} else {
		printMutex.Lock()
		ctwatch.DumpLogEntry(os.Stdout, scanner.LogUri, entry)
		fmt.Fprintf(os.Stdout, "\n")
		printMutex.Unlock()
	}
}

func defangLogUri (logUri string) string {
	return strings.Replace(strings.Replace(logUri, "://", "_", 1), "/", "_", -1)
}

func Main (argStateDir string, matcher ctwatch.Matcher) {
	stateDir = argStateDir

	var logs []string
	if *logsFilename != "" {
		logFile, err := os.Open(*logsFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error opening logs file for reading: %s: %s\n", os.Args[0], *logsFilename, err)
			os.Exit(3)
		}
		defer logFile.Close()
		scanner := bufio.NewScanner(logFile)
		for scanner.Scan() {
			logs = append(logs, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error reading logs file: %s: %s\n", os.Args[0], *logsFilename, err)
			os.Exit(3)
		}
	} else {
		logs = defaultLogs
	}

	if err := os.Mkdir(stateDir, 0777); err != nil && !os.IsExist(err) {
		fmt.Fprintf(os.Stderr, "%s: Error creating state directory: %s: %s\n", os.Args[0], stateDir, err)
		os.Exit(3)
	}
	for _, subdir := range []string{"certs", "logs"} {
		path := filepath.Join(stateDir, subdir)
		if err := os.Mkdir(path, 0777); err != nil && !os.IsExist(err) {
			fmt.Fprintf(os.Stderr, "%s: Error creating state directory: %s: %s\n", os.Args[0], path, err)
			os.Exit(3)
		}
	}

	exitCode := 0

	for _, logUri := range logs {
		stateFilename := filepath.Join(stateDir, "logs", defangLogUri(logUri))
		startIndex, err := ctwatch.ReadStateFile(stateFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error reading state file: %s: %s\n", os.Args[0], stateFilename, err)
			os.Exit(3)
		}

		logClient := client.New(logUri)
		opts := ctwatch.ScannerOptions{
			Matcher:       matcher,
			BatchSize:     *batchSize,
			NumWorkers:    *numWorkers,
			ParallelFetch: *parallelFetch,
			Quiet:         !*verbose,
		}
		scanner := ctwatch.NewScanner(logUri, logClient, opts)

		endIndex, err := scanner.TreeSize()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error contacting log: %s: %s\n", os.Args[0], logUri, err)
			exitCode = 1
			continue
		}

		if startIndex != -1 {
			if err := scanner.Scan(startIndex, endIndex, logCallback); err != nil {
				fmt.Fprintf(os.Stderr, "%s: Error scanning log: %s: %s\n", os.Args[0], logUri, err)
				exitCode = 1
				continue
			}
		}

		if err := ctwatch.WriteStateFile(stateFilename, endIndex); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error writing state file: %s: %s\n", os.Args[0], stateFilename, err)
			os.Exit(3)
		}
	}

	os.Exit(exitCode)
}
