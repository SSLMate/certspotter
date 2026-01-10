// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"software.sslmate.com/src/certspotter"
)

var programName = os.Args[0]
var Version = "unknown"
var Source = "unknown"

func certspotterVersion() (string, string) {
	if buildinfo, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(buildinfo.Main.Version, "v") {
		return strings.TrimPrefix(buildinfo.Main.Version, "v"), buildinfo.Main.Path
	} else {
		return Version, Source
	}
}

func homedir() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("unable to determine home directory: %w", err))
	}
	return homedir
}

func startedBySupervisor() bool {
	return os.Getenv("SYSTEMD_EXEC_PID") == strconv.Itoa(os.Getpid())
}

func defaultStateDir() string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else if envVar := os.Getenv("STATE_DIRECTORY"); envVar != "" && startedBySupervisor() {
		return envVar
	} else {
		return filepath.Join(homedir(), ".certspotter")
	}
}

func fileExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
}

func readCertFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	} else {
		return os.ReadFile(path)
	}
}

func parseCertificate(certBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(certBytes)
	if block != nil {
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
		return nil, fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}
	return nil, fmt.Errorf("no PEM data found")
}

func computeTBSHash(certDER []byte) ([32]byte, error) {
	certInfo, err := certspotter.MakeCertInfoFromRawCert(certDER)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error parsing certificate: %w", err)
	}
	precertTBS, err := certspotter.ReconstructPrecertTBS(certInfo.TBS)
	if err != nil {
		return [32]byte{}, fmt.Errorf("error reconstructing precertificate TBSCertificate: %w", err)
	}
	return sha256.Sum256(precertTBS.Raw), nil
}

func createNotifiedMarker(stateDir string, tbsHash [32]byte) (string, error) {
	tbsHex := hex.EncodeToString(tbsHash[:])

	certsDir := filepath.Join(stateDir, "certs")
	tbsDir := filepath.Join(certsDir, tbsHex[0:2])
	notifiedPath := filepath.Join(tbsDir, "."+tbsHex+".notified")

	// Check if already notified
	if fileExists(notifiedPath) {
		return notifiedPath, nil
	}

	// Create certs directory if needed
	if err := os.Mkdir(certsDir, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("error creating certs directory: %w", err)
	}

	// Create TBS-specific subdirectory if needed
	if err := os.Mkdir(tbsDir, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("error creating directory: %w", err)
	}

	// Create marker file
	if err := os.WriteFile(notifiedPath, nil, 0666); err != nil {
		return "", fmt.Errorf("error creating marker file: %w", err)
	}

	return notifiedPath, nil
}

func main() {
	version, source := certspotterVersion()

	var flags struct {
		stateDir  string
		printhash bool
		version   bool
	}

	flag.StringVar(&flags.stateDir, "state_dir", defaultStateDir(), "State directory used by certspotter")
	flag.BoolVar(&flags.printhash, "printhash", false, "Instead of authorizing certificate, print its TBS hash")
	flag.BoolVar(&flags.version, "version", false, "Print version and exit")
	flag.Parse()

	if flags.version {
		fmt.Fprintf(os.Stdout, "certspotter-authorize version %s (%s)\n", version, source)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] -|CERTFILE...\n", programName)
		fmt.Fprintf(os.Stderr, "Purpose: suppress future certspotter notifications for a certificate and its corresponding precertificate.\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(2)
	}

	if len(args) > 1 {
		for _, arg := range args {
			if arg == "-" {
				fmt.Fprintf(os.Stderr, "%s: '-' must be the only argument when used\n", programName)
				os.Exit(2)
			}
		}
	}

	for _, certPath := range args {
		certBytes, err := readCertFile(certPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: error reading certificate: %s\n", programName, err)
			os.Exit(1)
		}

		certDER, err := parseCertificate(certBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", programName, certPath, err)
			os.Exit(1)
		}

		tbsHash, err := computeTBSHash(certDER)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %s\n", programName, certPath, err)
			os.Exit(1)
		}

		if flags.printhash {
			if certPath == "-" {
				fmt.Println(hex.EncodeToString(tbsHash[:]))
			} else {
				fmt.Printf("%s  %s\n", hex.EncodeToString(tbsHash[:]), certPath)
			}
		} else {
			_, err = createNotifiedMarker(flags.stateDir, tbsHash)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
				os.Exit(1)
			}
		}
	}

	os.Exit(0)
}
