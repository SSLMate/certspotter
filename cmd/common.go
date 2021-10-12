// Copyright (C) 2016-2017 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package cmd

import (
	"bytes"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sync"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/loglist"
)

const defaultLogList = "https://loglist.certspotter.org/monitor.json"

var batchSize = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries (advanced)")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers (advanced)")
var script = flag.String("script", "", "Script to execute when a matching certificate is found")
var logsURL = flag.String("logs", defaultLogList, "File path or URL of JSON list of logs to monitor")
var noSave = flag.Bool("no_save", false, "Do not save a copy of matching certificates")
var verbose = flag.Bool("verbose", false, "Be verbose")
var showVersion = flag.Bool("version", false, "Print version and exit")
var startAtEnd = flag.Bool("start_at_end", false, "Start monitoring logs from the end rather than the beginning")
var allTime = flag.Bool("all_time", false, "Scan certs from all time, not just since last scan")
var state *State

var printMutex sync.Mutex

func homedir() string {
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

func DefaultStateDir(programName string) string {
	return filepath.Join(homedir(), "."+programName)
}

func DefaultConfigDir(programName string) string {
	return filepath.Join(homedir(), "."+programName)
}

func LogEntry(info *certspotter.EntryInfo) {
	if !*noSave {
		var alreadyPresent bool
		var err error
		alreadyPresent, info.Filename, err = state.SaveCert(info.IsPrecert, info.FullChain)
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

func loadLogList() ([]*loglist.Log, error) {
	list, err := loglist.Load(*logsURL)
	if err != nil {
		return nil, fmt.Errorf("Error loading log list: %s", err)
	}
	return list.AllLogs(), nil
}

type logHandle struct {
	scanner     *certspotter.Scanner
	state       *LogState
	tree        *certspotter.CollapsedMerkleTree
	verifiedSTH *ct.SignedTreeHead
}

func makeLogHandle(logInfo *loglist.Log) (*logHandle, error) {
	ctlog := new(logHandle)

	logKey, err := x509.ParsePKIXPublicKey(logInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("Bad public key: %s", err)
	}
	ctlog.scanner = certspotter.NewScanner(logInfo.URL, logInfo.LogID, logKey, &certspotter.ScannerOptions{
		BatchSize:  *batchSize,
		NumWorkers: *numWorkers,
		Quiet:      !*verbose,
	})

	ctlog.state, err = state.OpenLogState(logInfo)
	if err != nil {
		return nil, fmt.Errorf("Error opening state directory: %s", err)
	}
	ctlog.tree, err = ctlog.state.GetTree()
	if err != nil {
		return nil, fmt.Errorf("Error loading tree: %s", err)
	}
	ctlog.verifiedSTH, err = ctlog.state.GetVerifiedSTH()
	if err != nil {
		return nil, fmt.Errorf("Error loading verified STH: %s", err)
	}

	if ctlog.tree == nil && ctlog.verifiedSTH == nil { // This branch can be removed eventually
		legacySTH, err := state.GetLegacySTH(logInfo)
		if err != nil {
			return nil, fmt.Errorf("Error loading legacy STH: %s", err)
		}
		if legacySTH != nil {
			log.Print(logInfo.URL, ": Initializing log state from legacy state directory")
			ctlog.tree, err = ctlog.scanner.MakeCollapsedMerkleTree(legacySTH)
			if err != nil {
				return nil, fmt.Errorf("Error reconstructing Merkle Tree for legacy STH: %s", err)
			}
			if err := ctlog.state.StoreTree(ctlog.tree); err != nil {
				return nil, fmt.Errorf("Error storing tree: %s", err)
			}
			if err := ctlog.state.StoreVerifiedSTH(legacySTH); err != nil {
				return nil, fmt.Errorf("Error storing verified STH: %s", err)
			}
			state.RemoveLegacySTH(logInfo)
		}
	}

	return ctlog, nil
}

func (ctlog *logHandle) refresh() error {
	if *verbose {
		log.Print(ctlog.scanner.LogUri, ": Retrieving latest STH from log")
	}
	latestSTH, err := ctlog.scanner.GetSTH()
	if err != nil {
		return fmt.Errorf("Error retrieving STH from log: %s", err)
	}
	if ctlog.verifiedSTH == nil {
		if *verbose {
			log.Printf("%s: No existing STH is known; presuming latest STH (%d) is valid", ctlog.scanner.LogUri, latestSTH.TreeSize)
		}
		ctlog.verifiedSTH = latestSTH
		if err := ctlog.state.StoreVerifiedSTH(ctlog.verifiedSTH); err != nil {
			return fmt.Errorf("Error storing verified STH: %s", err)
		}
	} else {
		if err := ctlog.state.StoreUnverifiedSTH(latestSTH); err != nil {
			return fmt.Errorf("Error storing unverified STH: %s", err)
		}
	}
	return nil
}

func (ctlog *logHandle) verifySTH(sth *ct.SignedTreeHead) error {
	isValid, err := ctlog.scanner.CheckConsistency(ctlog.verifiedSTH, sth)
	if err != nil {
		return fmt.Errorf("Error fetching consistency proof: %s", err)
	}
	if !isValid {
		return fmt.Errorf("Consistency proof between %d and %d is invalid", ctlog.verifiedSTH.TreeSize, sth.TreeSize)
	}
	return nil
}

func (ctlog *logHandle) audit() error {
	sths, err := ctlog.state.GetUnverifiedSTHs()
	if err != nil {
		return fmt.Errorf("Error loading unverified STHs: %s", err)
	}

	for _, sth := range sths {
		if *verbose {
			log.Printf("%s: Verifying consistency of STH %d (%x) with previously-verified STH %d (%x)", ctlog.scanner.LogUri, sth.TreeSize, sth.SHA256RootHash, ctlog.verifiedSTH.TreeSize, ctlog.verifiedSTH.SHA256RootHash)
		}
		if err := ctlog.verifySTH(sth); err != nil {
			log.Printf("%s: Unable to verify consistency of STH %d (%s) (if this error persists, it should be construed as misbehavior by the log): %s", ctlog.scanner.LogUri, sth.TreeSize, ctlog.state.UnverifiedSTHFilename(sth), err)
			continue
		}
		if sth.TreeSize > ctlog.verifiedSTH.TreeSize {
			if *verbose {
				log.Printf("%s: STH %d (%x) is now the latest verified STH", ctlog.scanner.LogUri, sth.TreeSize, sth.SHA256RootHash)
			}
			ctlog.verifiedSTH = sth
			if err := ctlog.state.StoreVerifiedSTH(ctlog.verifiedSTH); err != nil {
				return fmt.Errorf("Error storing verified STH: %s", err)
			}
		}
		if err := ctlog.state.RemoveUnverifiedSTH(sth); err != nil {
			return fmt.Errorf("Error removing redundant STH: %s", err)
		}
	}

	return nil
}

func (ctlog *logHandle) scan(processCallback certspotter.ProcessCallback) error {
	startIndex := int64(ctlog.tree.GetSize())
	endIndex := int64(ctlog.verifiedSTH.TreeSize)

	if endIndex > startIndex {
		tree := certspotter.CloneCollapsedMerkleTree(ctlog.tree)

		if err := ctlog.scanner.Scan(startIndex, endIndex, processCallback, tree); err != nil {
			return fmt.Errorf("Error scanning log (if this error persists, it should be construed as misbehavior by the log): %s", err)
		}

		rootHash := tree.CalculateRoot()
		if !bytes.Equal(rootHash, ctlog.verifiedSTH.SHA256RootHash[:]) {
			return fmt.Errorf("Log has misbehaved: log entries at tree size %d do not correspond to signed tree root", ctlog.verifiedSTH.TreeSize)
		}

		ctlog.tree = tree
		if err := ctlog.state.StoreTree(ctlog.tree); err != nil {
			return fmt.Errorf("Error storing tree: %s", err)
		}
	}

	return nil
}

func processLog(logInfo *loglist.Log, processCallback certspotter.ProcessCallback) int {
	ctlog, err := makeLogHandle(logInfo)
	if err != nil {
		log.Print(logInfo.URL, ": ", err)
		return 1
	}

	if err := ctlog.refresh(); err != nil {
		log.Print(logInfo.URL, ": ", err)
		return 1
	}

	if err := ctlog.audit(); err != nil {
		log.Print(logInfo.URL, ": ", err)
		return 1
	}

	if *allTime {
		ctlog.tree = certspotter.EmptyCollapsedMerkleTree()
		if *verbose {
			log.Printf("%s: Scanning all %d entries in the log because -all_time option specified", logInfo.URL, ctlog.verifiedSTH.TreeSize)
		}
	} else if ctlog.tree != nil {
		if *verbose {
			log.Printf("%s: Existing log; scanning %d new entries since previous scan", logInfo.URL, ctlog.verifiedSTH.TreeSize-ctlog.tree.GetSize())
		}
	} else if *startAtEnd {
		ctlog.tree, err = ctlog.scanner.MakeCollapsedMerkleTree(ctlog.verifiedSTH)
		if err != nil {
			log.Printf("%s: Error reconstructing Merkle Tree: %s", logInfo.URL, err)
			return 1
		}
		if *verbose {
			log.Printf("%s: New log; not scanning %d existing entries because -start_at_end option was specified", logInfo.URL, ctlog.verifiedSTH.TreeSize)
		}
	} else {
		ctlog.tree = certspotter.EmptyCollapsedMerkleTree()
		if *verbose {
			log.Printf("%s: New log; scanning all %d entries in the log (use the -start_at_end option to scan new logs from the end rather than the beginning)", logInfo.URL, ctlog.verifiedSTH.TreeSize)
		}
	}
	if err := ctlog.state.StoreTree(ctlog.tree); err != nil {
		log.Printf("%s: Error storing tree: %s\n", logInfo.URL, err)
		return 1
	}

	if err := ctlog.scan(processCallback); err != nil {
		log.Print(logInfo.URL, ": ", err)
		return 1
	}

	if *verbose {
		log.Printf("%s: Final log size = %d, final root hash = %x", logInfo.URL, ctlog.verifiedSTH.TreeSize, ctlog.verifiedSTH.SHA256RootHash)
	}

	return 0
}

func ParseFlags() {
	flag.Parse()
	if *showVersion {
		fmt.Fprintf(os.Stdout, "Cert Spotter %s\n", certspotter.Version)
		os.Exit(0)
	}
}

func Main(statePath string, processCallback certspotter.ProcessCallback) int {
	var err error

	logs, err := loadLogList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
		return 1
	}

	state, err = OpenState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
		return 1
	}
	locked, err := state.Lock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Error locking state directory: %s\n", os.Args[0], err)
		return 1
	}
	if !locked {
		var otherPidInfo string
		if otherPid := state.LockingPid(); otherPid != 0 {
			otherPidInfo = fmt.Sprintf(" (as process ID %d)", otherPid)
		}
		fmt.Fprintf(os.Stderr, "%s: Another instance of %s is already running%s; remove the file %s if this is not the case\n", os.Args[0], os.Args[0], otherPidInfo, state.LockFilename())
		return 1
	}

	processLogResults := make(chan int)
	for _, logInfo := range logs {
		go func(logInfo *loglist.Log) {
			processLogResults <- processLog(logInfo, processCallback)
		}(logInfo)
	}

	exitCode := 0
	for range logs {
		exitCode |= <-processLogResults
	}

	if state.IsFirstRun() && exitCode == 0 {
		if err := state.WriteOnceFile(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error writing once file: %s\n", os.Args[0], err)
			exitCode |= 1
		}
	}

	if err := state.Unlock(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: Error unlocking state directory: %s\n", os.Args[0], err)
		exitCode |= 1
	}

	return exitCode
}
