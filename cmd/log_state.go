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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
)

type LogState struct {
	path	string
}

// generate a filename that uniquely identifies the STH (within the context of a particular log)
func sthFilename (sth *ct.SignedTreeHead) string {
	hasher := sha256.New()
	switch sth.Version {
	case ct.V1:
		binary.Write(hasher, binary.LittleEndian, sth.Timestamp)
		binary.Write(hasher, binary.LittleEndian, sth.SHA256RootHash)
	default:
		panic(fmt.Sprintf("Unsupported STH version %d", sth.Version))
	}
	// For 6962-bis, we will need to handle a variable-length root hash, and include the signature in the filename hash (since signatures must be deterministic)
	return strconv.FormatUint(sth.TreeSize, 10) + "-" + base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

func makeLogStateDir (logStatePath string) error {
	if err := os.Mkdir(logStatePath, 0777); err != nil && !os.IsExist(err) {
		return fmt.Errorf("%s: %s", logStatePath, err)
	}
	for _, subdir := range []string{"unverified_sths"} {
		path := filepath.Join(logStatePath, subdir)
		if err := os.Mkdir(path, 0777); err != nil && !os.IsExist(err) {
			return fmt.Errorf("%s: %s", path, err)
		}
	}
	return nil
}

func OpenLogState (logStatePath string) (*LogState, error) {
	if err := makeLogStateDir(logStatePath); err != nil {
		return nil, fmt.Errorf("Error creating log state directory: %s", err)
	}
	return &LogState{path: logStatePath}, nil
}

func (logState *LogState) VerifiedSTHFilename () string {
	return filepath.Join(logState.path, "verified_sth")
}

func (logState *LogState) GetVerifiedSTH () (*ct.SignedTreeHead, error) {
	sth, err := readSTHFile(logState.VerifiedSTHFilename())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return sth, nil
}

func (logState *LogState) StoreVerifiedSTH (sth *ct.SignedTreeHead) error {
	return writeJSONFile(logState.VerifiedSTHFilename(), sth, 0666)
}

func (logState *LogState) GetUnverifiedSTHs () ([]*ct.SignedTreeHead, error) {
	dir, err := os.Open(filepath.Join(logState.path, "unverified_sths"))
	if err != nil {
		if os.IsNotExist(err) {
			return []*ct.SignedTreeHead{}, nil
		} else {
			return nil, err
		}
	}
	filenames, err := dir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	sths := make([]*ct.SignedTreeHead, 0, len(filenames))
	for _, filename := range filenames {
		if !strings.HasPrefix(filename, ".") {
			sth, _ := readSTHFile(filepath.Join(dir.Name(), filename))
			if sth != nil {
				sths = append(sths, sth)
			}
		}
	}
	return sths, nil
}

func (logState *LogState) UnverifiedSTHFilename (sth *ct.SignedTreeHead) string {
	return filepath.Join(logState.path, "unverified_sths", sthFilename(sth))
}

func (logState *LogState) StoreUnverifiedSTH (sth *ct.SignedTreeHead) error {
	filename := logState.UnverifiedSTHFilename(sth)
	if fileExists(filename) {
		return nil
	}
	return writeJSONFile(filename, sth, 0666)
}

func (logState *LogState) RemoveUnverifiedSTH (sth *ct.SignedTreeHead) error {
	filename := logState.UnverifiedSTHFilename(sth)
	err := os.Remove(filepath.Join(filename))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (logState *LogState) GetLogPosition () (*certspotter.CollapsedMerkleTree, error) {
	tree := new(certspotter.CollapsedMerkleTree)
	if err := readJSONFile(filepath.Join(logState.path, "position"), tree); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return tree, nil
}

func (logState *LogState) StoreLogPosition (tree *certspotter.CollapsedMerkleTree) error {
	return writeJSONFile(filepath.Join(logState.path, "position"), tree, 0666)
}
