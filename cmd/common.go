package cmd

import (
	"flag"
	"fmt"
	"log"
	"os"
	"bytes"
	"os/user"
	"encoding/json"
	"sync"
	"strings"
	"path/filepath"

	"src.agwa.name/ctwatch"
)

var batchSize = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers")
var parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
var script = flag.String("script", "", "Script to execute when a matching certificate is found")
var logsFilename = flag.String("logs", "", "JSON file containing log URLs")
var underwater = flag.Bool("underwater", false, "Monitor certificates from distrusted CAs")
var noSave = flag.Bool("no_save", false, "Do not save a copy of matching certificates")
var verbose = flag.Bool("verbose", false, "Be verbose")
var allTime = flag.Bool("all_time", false, "Scan certs from all time, not just since last scan")
var stateDir string

var printMutex sync.Mutex

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

func LogEntry (info *ctwatch.EntryInfo) {
	if !*noSave {
		var alreadyPresent bool
		var err error
		alreadyPresent, info.Filename, err = ctwatch.WriteCertRepository(filepath.Join(stateDir, "certs"), info.Entry)
		if err != nil {
			log.Print(err)
		}
		if alreadyPresent {
			return
		}
	}

	if *script != "" {
		if err := info.InvokeHookScript(*script); err != nil {
			log.Print(err)
		}
	} else {
		printMutex.Lock()
		info.Write(os.Stdout)
		fmt.Fprintf(os.Stdout, "\n")
		printMutex.Unlock()
	}
}

func defangLogUri (logUri string) string {
	return strings.Replace(strings.Replace(logUri, "://", "_", 1), "/", "_", -1)
}

func Main (argStateDir string, processCallback ctwatch.ProcessCallback) {
	stateDir = argStateDir

	var logs []ctwatch.LogInfo
	if *logsFilename != "" {
		logFile, err := os.Open(*logsFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error opening logs file for reading: %s: %s\n", os.Args[0], *logsFilename, err)
			os.Exit(3)
		}
		defer logFile.Close()
		var logFileObj ctwatch.LogInfoFile
		if err := json.NewDecoder(logFile).Decode(&logFileObj); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error decoding logs file: %s: %s\n", os.Args[0], *logsFilename, err)
			os.Exit(3)
		}
		logs = logFileObj.Logs
	} else if *underwater {
		logs = ctwatch.UnderwaterLogs
	} else {
		logs = ctwatch.DefaultLogs
	}

	if err := os.Mkdir(stateDir, 0777); err != nil && !os.IsExist(err) {
		fmt.Fprintf(os.Stderr, "%s: Error creating state directory: %s: %s\n", os.Args[0], stateDir, err)
		os.Exit(3)
	}
	for _, subdir := range []string{"certs", "sths"} {
		path := filepath.Join(stateDir, subdir)
		if err := os.Mkdir(path, 0777); err != nil && !os.IsExist(err) {
			fmt.Fprintf(os.Stderr, "%s: Error creating state directory: %s: %s\n", os.Args[0], path, err)
			os.Exit(3)
		}
	}

	exitCode := 0

	for _, logInfo := range logs {
		logUri := logInfo.FullURI()
		logKey, err := logInfo.ParsedPublicKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: Bad public key: %s\n", os.Args[0], logUri, err)
			os.Exit(3)
		}
		stateFilename := filepath.Join(stateDir, "sths", defangLogUri(logUri))
		prevSTH, err := ctwatch.ReadSTHFile(stateFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error reading state file: %s: %s\n", os.Args[0], stateFilename, err)
			os.Exit(3)
		}

		opts := ctwatch.ScannerOptions{
			BatchSize:     *batchSize,
			NumWorkers:    *numWorkers,
			ParallelFetch: *parallelFetch,
			Quiet:         !*verbose,
		}
		scanner := ctwatch.NewScanner(logUri, logKey, opts)

		latestSTH, err := scanner.GetSTH()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error contacting log: %s: %s\n", os.Args[0], logUri, err)
			exitCode = 1
			continue
		}

		var startIndex uint64
		if *allTime {
			startIndex = 0
		} else if prevSTH != nil {
			startIndex = prevSTH.TreeSize
		} else {
			startIndex = latestSTH.TreeSize
		}

		if latestSTH.TreeSize > startIndex {
			var treeBuilder *ctwatch.MerkleTreeBuilder
			if prevSTH != nil {
				var valid bool
				var err error
				valid, treeBuilder, err = scanner.CheckConsistency(prevSTH, latestSTH)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: Error fetching consistency proof: %s: %s\n", os.Args[0], logUri, err)
					exitCode = 1
					continue
				}
				if !valid {
					fmt.Fprintf(os.Stderr, "%s: %s: Consistency proof failed!\n", os.Args[0], logUri)
					exitCode = 1
					continue
				}
			} else {
				treeBuilder = &ctwatch.MerkleTreeBuilder{}
			}

			if err := scanner.Scan(int64(startIndex), int64(latestSTH.TreeSize), processCallback, treeBuilder); err != nil {
				fmt.Fprintf(os.Stderr, "%s: Error scanning log: %s: %s\n", os.Args[0], logUri, err)
				exitCode = 1
				continue
			}

			rootHash := treeBuilder.Finish()
			if !bytes.Equal(rootHash, latestSTH.SHA256RootHash[:]) {
				fmt.Fprintf(os.Stderr, "%s: %s: Validation of log entries failed - calculated tree root (%x) does not match signed tree root (%s)\n", os.Args[0], logUri, rootHash, latestSTH.SHA256RootHash)
				exitCode = 1
				continue
			}
		}

		if err := ctwatch.WriteSTHFile(stateFilename, latestSTH); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error writing state file: %s: %s\n", os.Args[0], stateFilename, err)
			os.Exit(3)
		}
	}

	os.Exit(exitCode)
}
