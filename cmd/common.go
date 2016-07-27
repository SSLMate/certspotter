// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

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
	"time"
	"strconv"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
)

var batchSize = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries (advanced)")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers (advanced)")
var script = flag.String("script", "", "Script to execute when a matching certificate is found")
var logsFilename = flag.String("logs", "", "JSON file containing log information")
var underwater = flag.Bool("underwater", false, "Monitor certificates from distrusted CAs instead of trusted CAs")
var noSave = flag.Bool("no_save", false, "Do not save a copy of matching certificates")
var verbose = flag.Bool("verbose", false, "Be verbose")
var allTime = flag.Bool("all_time", false, "Scan certs from all time, not just since last scan")
var stateDir string

var printMutex sync.Mutex

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
	return filepath.Join(homedir(), "." + programName)
}

func DefaultConfigDir (programName string) string {
	return filepath.Join(homedir(), "." + programName)
}

func LogEntry (info *certspotter.EntryInfo) {
	if !*noSave {
		var alreadyPresent bool
		var err error
		alreadyPresent, info.Filename, err = certspotter.WriteCertRepository(filepath.Join(stateDir, "certs"), info.IsPrecert, info.FullChain)
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

func saveEvidence (logUri string, firstSTH *ct.SignedTreeHead, secondSTH *ct.SignedTreeHead, proof ct.ConsistencyProof) (string, string, string, error) {
	now := strconv.FormatInt(time.Now().Unix(), 10)

	firstFilename := filepath.Join(stateDir, "evidence", defangLogUri(logUri) + ".inconsistent." + now + ".first")
	if err := certspotter.WriteSTHFile(firstFilename, firstSTH); err != nil {
		return "", "", "", err
	}

	secondFilename := filepath.Join(stateDir, "evidence", defangLogUri(logUri) + ".inconsistent." + now + ".second")
	if err := certspotter.WriteSTHFile(secondFilename, secondSTH); err != nil {
		return "", "", "", err
	}

	proofFilename := filepath.Join(stateDir, "evidence", defangLogUri(logUri) + ".inconsistent." + now + ".proof")
	if err := certspotter.WriteProofFile(proofFilename, proof); err != nil {
		return "", "", "", err
	}

	return firstFilename, secondFilename, proofFilename, nil
}

func Main (argStateDir string, processCallback certspotter.ProcessCallback) int {
	stateDir = argStateDir

	var logs []certspotter.LogInfo
	if *logsFilename != "" {
		logFile, err := os.Open(*logsFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error opening logs file for reading: %s: %s\n", os.Args[0], *logsFilename, err)
			return 1
		}
		defer logFile.Close()
		var logFileObj certspotter.LogInfoFile
		if err := json.NewDecoder(logFile).Decode(&logFileObj); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error decoding logs file: %s: %s\n", os.Args[0], *logsFilename, err)
			return 1
		}
		logs = logFileObj.Logs
	} else if *underwater {
		logs = certspotter.UnderwaterLogs
	} else {
		logs = certspotter.DefaultLogs
	}

	if err := os.Mkdir(stateDir, 0777); err != nil && !os.IsExist(err) {
		fmt.Fprintf(os.Stderr, "%s: Error creating state directory: %s: %s\n", os.Args[0], stateDir, err)
		return 1
	}
	for _, subdir := range []string{"certs", "sths", "evidence"} {
		path := filepath.Join(stateDir, subdir)
		if err := os.Mkdir(path, 0777); err != nil && !os.IsExist(err) {
			fmt.Fprintf(os.Stderr, "%s: Error creating state directory: %s: %s\n", os.Args[0], path, err)
			return 1
		}
	}

	/*
	 * Exit code bits:
	 *  1 = initialization/configuration/system error
	 *  2 = usage error
	 *  4 = error communicating with log
	 *  8 = log misbehavior
	 */
	exitCode := 0

	for _, logInfo := range logs {
		logUri := logInfo.FullURI()
		log.SetPrefix(os.Args[0] + ": " + logUri + ": ")
		logKey, err := logInfo.ParsedPublicKey()
		if err != nil {
			log.Printf("Bad public key: %s\n", err)
			exitCode |= 1
			continue
		}
		stateFilename := filepath.Join(stateDir, "sths", defangLogUri(logUri))
		prevSTH, err := certspotter.ReadSTHFile(stateFilename)
		if err != nil {
			log.Printf("Error reading state file: %s: %s\n", stateFilename, err)
			exitCode |= 1
			continue
		}

		opts := certspotter.ScannerOptions{
			BatchSize:     *batchSize,
			NumWorkers:    *numWorkers,
			Quiet:         !*verbose,
		}
		scanner := certspotter.NewScanner(logUri, logKey, &opts)

		latestSTH, err := scanner.GetSTH()
		if err != nil {
			log.Printf("Error retrieving STH from log: %s\n", err)
			exitCode |= 4
			continue
		}

		if *verbose {
			if prevSTH != nil {
				log.Printf("Existing log; scanning %d new entries since previous scan (previous size %d, previous root hash = %x)", latestSTH.TreeSize - prevSTH.TreeSize, prevSTH.TreeSize, prevSTH.SHA256RootHash)
			} else if *allTime {
				log.Printf("new log; scanning all %d entries in the log", latestSTH.TreeSize)
			} else {
				log.Printf("new log; not scanning existing entries because -all_time option not specified")
			}
		}

		var startIndex uint64
		if prevSTH != nil {
			startIndex = prevSTH.TreeSize
		} else if *allTime {
			startIndex = 0
		} else {
			startIndex = latestSTH.TreeSize
		}

		if latestSTH.TreeSize > startIndex {
			var treeBuilder *certspotter.MerkleTreeBuilder
			if prevSTH != nil {
				var valid bool
				var err error
				var proof ct.ConsistencyProof
				valid, treeBuilder, proof, err = scanner.CheckConsistency(prevSTH, latestSTH)
				if err != nil {
					log.Printf("Error fetching consistency proof: %s\n", err)
					exitCode |= 4
					continue
				}
				if !valid {
					firstFilename, secondFilename, proofFilename, err := saveEvidence(logUri, prevSTH, latestSTH, proof)
					if err != nil {
						log.Printf("Consistency proof failed - the log has misbehaved!  Saving evidence of misbehavior failed: %s\n", err)
					} else {
						log.Printf("Consistency proof failed - the log has misbehaved!  Evidence of misbehavior has been saved to '%s' and '%s' (with proof in '%s').\n", firstFilename, secondFilename, proofFilename)
					}
					exitCode |= 8
					continue
				}
			} else {
				treeBuilder = &certspotter.MerkleTreeBuilder{}
			}

			if err := scanner.Scan(int64(startIndex), int64(latestSTH.TreeSize), processCallback, treeBuilder); err != nil {
				log.Printf("Error scanning log: %s\n", err)
				exitCode |= 4
				continue
			}

			rootHash := treeBuilder.Finish()
			if !bytes.Equal(rootHash, latestSTH.SHA256RootHash[:]) {
				log.Printf("Validation of log entries failed - calculated tree root (%x) does not match signed tree root (%s).  If this error persists for an extended period, it should be construed as misbehavior by the log.\n", rootHash, latestSTH.SHA256RootHash)
				exitCode |= 8
				continue
			}
		}

		if *verbose {
			log.Printf("final log size = %d, final root hash = %x", latestSTH.TreeSize, latestSTH.SHA256RootHash)
		}

		if err := certspotter.WriteSTHFile(stateFilename, latestSTH); err != nil {
			log.Printf("Error writing state file: %s: %s\n", stateFilename, err)
			exitCode |= 1
			continue
		}
	}

	return exitCode
}
