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
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sync"

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
var proxy = flag.String("proxyurl", "", "Proxy URL to use for http connections (eg. http://my.proxy.com:8080)")
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

func loadLogList() ([]certspotter.LogInfo, error) {
	if *logsFilename != "" {
		var logFileObj certspotter.LogInfoFile
		if err := readJSONFile(*logsFilename, &logFileObj); err != nil {
			return nil, fmt.Errorf("Error reading logs file: %s: %s", *logsFilename, err)
		}
		return logFileObj.Logs, nil
	} else if *underwater {
		return certspotter.UnderwaterLogs, nil
	} else {
		return certspotter.DefaultLogs, nil
	}
}

type logHandle struct {
	scanner     *certspotter.Scanner
	state       *LogState
	tree        *certspotter.CollapsedMerkleTree
	verifiedSTH *ct.SignedTreeHead
}

func makeLogHandle(logInfo *certspotter.LogInfo) (*logHandle, error) {
	ctlog := new(logHandle)

	logKey, err := logInfo.ParsedPublicKey()
	if err != nil {
		return nil, fmt.Errorf("Bad public key: %s", err)
	}

	proxyURL, err := url.Parse(*proxy)
	if *proxy == "" {
		proxyURL = nil
	}

	ctlog.scanner = certspotter.NewScanner(logInfo.FullURI(), logInfo.ID(), logKey, &certspotter.ScannerOptions{
		BatchSize:  *batchSize,
		NumWorkers: *numWorkers,
		Quiet:      !*verbose,
		ProxyURL:   proxyURL})

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
			log.Printf("Initializing log state from legacy state directory")
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
		log.Printf("Retrieving latest STH from log")
	}
	latestSTH, err := ctlog.scanner.GetSTH()
	if err != nil {
		return fmt.Errorf("Error retrieving STH from log: %s", err)
	}
	if ctlog.verifiedSTH == nil {
		if *verbose {
			log.Printf("No existing STH is known; presuming latest STH (%d) is valid", latestSTH.TreeSize)
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
			log.Printf("Verifying consistency of STH %d (%x) with previously-verified STH %d (%x)", sth.TreeSize, sth.SHA256RootHash, ctlog.verifiedSTH.TreeSize, ctlog.verifiedSTH.SHA256RootHash)
		}
		if err := ctlog.verifySTH(sth); err != nil {
			log.Printf("Unable to verify consistency of STH %d (%s) (if this error persists, it should be construed as misbehavior by the log): %s", sth.TreeSize, ctlog.state.UnverifiedSTHFilename(sth), err)
			continue
		}
		if sth.TreeSize > ctlog.verifiedSTH.TreeSize {
			if *verbose {
				log.Printf("STH %d (%x) is now the latest verified STH", sth.TreeSize, sth.SHA256RootHash)
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

func processLog(logInfo *certspotter.LogInfo, processCallback certspotter.ProcessCallback) int {
	log.SetPrefix(os.Args[0] + ": " + logInfo.Url + ": ")

	ctlog, err := makeLogHandle(logInfo)
	if err != nil {
		log.Printf("%s\n", err)
		return 1
	}

	if err := ctlog.refresh(); err != nil {
		log.Printf("%s\n", err)
		return 1
	}

	if err := ctlog.audit(); err != nil {
		log.Printf("%s\n", err)
		return 1
	}

	if *allTime {
		ctlog.tree = certspotter.EmptyCollapsedMerkleTree()
		if *verbose {
			log.Printf("Scanning all %d entries in the log because -all_time option specified", ctlog.verifiedSTH.TreeSize)
		}
	} else if ctlog.tree != nil {
		if *verbose {
			log.Printf("Existing log; scanning %d new entries since previous scan", ctlog.verifiedSTH.TreeSize-ctlog.tree.GetSize())
		}
	} else if state.IsFirstRun() {
		ctlog.tree, err = ctlog.scanner.MakeCollapsedMerkleTree(ctlog.verifiedSTH)
		if err != nil {
			log.Printf("Error reconstructing Merkle Tree: %s", err)
			return 1
		}
		if *verbose {
			log.Printf("First run of Cert Spotter; not scanning %d existing entries because -all_time option not specified", ctlog.verifiedSTH.TreeSize)
		}
	} else {
		ctlog.tree = certspotter.EmptyCollapsedMerkleTree()
		if *verbose {
			log.Printf("New log; scanning all %d entries in the log", ctlog.verifiedSTH.TreeSize)
		}
	}
	if err := ctlog.state.StoreTree(ctlog.tree); err != nil {
		log.Printf("Error storing tree: %s\n", err)
		return 1
	}

	if err := ctlog.scan(processCallback); err != nil {
		log.Printf("%s\n", err)
		return 1
	}

	if *verbose {
		log.Printf("Final log size = %d, final root hash = %x", ctlog.verifiedSTH.TreeSize, ctlog.verifiedSTH.SHA256RootHash)
	}

	return 0
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

	exitCode := 0
	for i := range logs {
		exitCode |= processLog(&logs[i], processCallback)
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
