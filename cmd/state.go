// Copyright (C) 2017 Opsmate, Inc.
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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/loglist"
)

type State struct {
	path string
}

func legacySTHFilename(logInfo *loglist.Log) string {
	return strings.Replace(strings.Replace(logInfo.URL, "://", "_", 1), "/", "_", -1)
}

func readVersionFile(statePath string) (int, error) {
	versionFilePath := filepath.Join(statePath, "version")
	versionBytes, err := ioutil.ReadFile(versionFilePath)
	if err == nil {
		version, err := strconv.Atoi(string(bytes.TrimSpace(versionBytes)))
		if err != nil {
			return -1, fmt.Errorf("%s: contains invalid integer: %s", versionFilePath, err)
		}
		if version < 0 {
			return -1, fmt.Errorf("%s: contains negative integer", versionFilePath)
		}
		return version, nil
	} else if os.IsNotExist(err) {
		if fileExists(filepath.Join(statePath, "sths")) {
			// Original version of certspotter had no version file.
			// Infer version 0 if "sths" directory is present.
			return 0, nil
		}
		return -1, nil
	} else {
		return -1, fmt.Errorf("%s: %s", versionFilePath, err)
	}
}

func writeVersionFile(statePath string) error {
	version := 1
	versionString := fmt.Sprintf("%d\n", version)
	versionFilePath := filepath.Join(statePath, "version")
	if err := ioutil.WriteFile(versionFilePath, []byte(versionString), 0666); err != nil {
		return fmt.Errorf("%s: %s\n", versionFilePath, err)
	}
	return nil
}

func makeStateDir(statePath string) error {
	if err := os.Mkdir(statePath, 0777); err != nil && !os.IsExist(err) {
		return fmt.Errorf("%s: %s", statePath, err)
	}
	for _, subdir := range []string{"certs", "logs"} {
		path := filepath.Join(statePath, subdir)
		if err := os.Mkdir(path, 0777); err != nil && !os.IsExist(err) {
			return fmt.Errorf("%s: %s", path, err)
		}
	}
	return nil
}

func OpenState(statePath string) (*State, error) {
	version, err := readVersionFile(statePath)
	if err != nil {
		return nil, fmt.Errorf("Error reading version file: %s", err)
	}

	if version < 1 {
		if err := makeStateDir(statePath); err != nil {
			return nil, fmt.Errorf("Error creating state directory: %s", err)
		}
		if version == 0 {
			log.Printf("Migrating state directory (%s) to new layout...", statePath)
			if err := os.Rename(filepath.Join(statePath, "sths"), filepath.Join(statePath, "legacy_sths")); err != nil {
				return nil, fmt.Errorf("Error migrating STHs directory: %s", err)
			}
			for _, subdir := range []string{"evidence", "legacy_sths"} {
				os.Remove(filepath.Join(statePath, subdir))
			}
			if err := ioutil.WriteFile(filepath.Join(statePath, "once"), []byte{}, 0666); err != nil {
				return nil, fmt.Errorf("Error creating once file: %s", err)
			}
		}
		if err := writeVersionFile(statePath); err != nil {
			return nil, fmt.Errorf("Error writing version file: %s", err)
		}
	} else if version > 1 {
		return nil, fmt.Errorf("%s was created by a newer version of Cert Spotter; please remove this directory or upgrade Cert Spotter", statePath)
	}

	return &State{path: statePath}, nil
}

func (state *State) IsFirstRun() bool {
	return !fileExists(filepath.Join(state.path, "once"))
}

func (state *State) WriteOnceFile() error {
	if err := ioutil.WriteFile(filepath.Join(state.path, "once"), []byte{}, 0666); err != nil {
		return fmt.Errorf("Error writing once file: %s", err)
	}
	return nil
}

func (state *State) SaveCert(isPrecert bool, certs [][]byte) (bool, string, error) {
	if len(certs) == 0 {
		return false, "", fmt.Errorf("Cannot write an empty certificate chain")
	}

	fingerprint := sha256hex(certs[0])
	prefixPath := filepath.Join(state.path, "certs", fingerprint[0:2])
	var filenameSuffix string
	if isPrecert {
		filenameSuffix = ".precert.pem"
	} else {
		filenameSuffix = ".cert.pem"
	}
	if err := os.Mkdir(prefixPath, 0777); err != nil && !os.IsExist(err) {
		return false, "", fmt.Errorf("Failed to create prefix directory %s: %s", prefixPath, err)
	}
	path := filepath.Join(prefixPath, fingerprint+filenameSuffix)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return true, path, nil
		} else {
			return false, path, fmt.Errorf("Failed to open %s for writing: %s", path, err)
		}
	}
	for _, cert := range certs {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			file.Close()
			return false, path, fmt.Errorf("Error writing to %s: %s", path, err)
		}
	}
	if err := file.Close(); err != nil {
		return false, path, fmt.Errorf("Error writing to %s: %s", path, err)
	}

	return false, path, nil
}

func (state *State) OpenLogState(logInfo *loglist.Log) (*LogState, error) {
	return OpenLogState(filepath.Join(state.path, "logs", base64.RawURLEncoding.EncodeToString(logInfo.LogID[:])))
}

func (state *State) GetLegacySTH(logInfo *loglist.Log) (*ct.SignedTreeHead, error) {
	sth, err := readSTHFile(filepath.Join(state.path, "legacy_sths", legacySTHFilename(logInfo)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return sth, nil
}
func (state *State) RemoveLegacySTH(logInfo *loglist.Log) error {
	err := os.Remove(filepath.Join(state.path, "legacy_sths", legacySTHFilename(logInfo)))
	os.Remove(filepath.Join(state.path, "legacy_sths"))
	return err
}
func (state *State) LockFilename() string {
	return filepath.Join(state.path, "lock")
}
func (state *State) Lock() (bool, error) {
	file, err := os.OpenFile(state.LockFilename(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		} else {
			return false, err
		}
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		file.Close()
		os.Remove(state.LockFilename())
		return false, err
	}
	if err := file.Close(); err != nil {
		os.Remove(state.LockFilename())
		return false, err
	}
	return true, nil
}
func (state *State) Unlock() error {
	return os.Remove(state.LockFilename())
}
func (state *State) LockingPid() int {
	pidBytes, err := ioutil.ReadFile(state.LockFilename())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(pidBytes)))
	if err != nil {
		return 0
	}
	return pid
}
