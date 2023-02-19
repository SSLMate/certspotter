// Copyright (C) 2017, 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
	"io/fs"
	"os"
	"path/filepath"
	"software.sslmate.com/src/certspotter/ct"
	"strconv"
	"strings"
)

func loadSTHsFromDir(dirPath string) ([]*ct.SignedTreeHead, error) {
	entries, err := os.ReadDir(dirPath)
	if errors.Is(err, fs.ErrNotExist) {
		return []*ct.SignedTreeHead{}, nil
	} else if err != nil {
		return nil, err
	}
	sths := make([]*ct.SignedTreeHead, 0, len(entries))
	for _, entry := range entries {
		filename := entry.Name()
		if strings.HasPrefix(filename, ".") || !strings.HasSuffix(filename, ".json") {
			continue
		}
		sth, err := readSTHFile(filepath.Join(dirPath, filename))
		if err != nil {
			return nil, err
		}
		sths = append(sths, sth)
	}
	slices.SortFunc(sths, func(a, b *ct.SignedTreeHead) bool { return a.TreeSize < b.TreeSize })
	return sths, nil
}

func readSTHFile(filePath string) (*ct.SignedTreeHead, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	sth := new(ct.SignedTreeHead)
	if err := json.Unmarshal(fileBytes, sth); err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", filePath, err)
	}
	return sth, nil
}

func storeSTHInDir(dirPath string, sth *ct.SignedTreeHead) error {
	filePath := filepath.Join(dirPath, sthFilename(sth))
	if fileExists(filePath) {
		return nil
	}
	return writeJSONFile(filePath, sth, 0666)
}

func removeSTHFromDir(dirPath string, sth *ct.SignedTreeHead) error {
	filePath := filepath.Join(dirPath, sthFilename(sth))
	err := os.Remove(filePath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// generate a filename that uniquely identifies the STH (within the context of a particular log)
func sthFilename(sth *ct.SignedTreeHead) string {
	hasher := sha256.New()
	switch sth.Version {
	case ct.V1:
		binary.Write(hasher, binary.LittleEndian, sth.Timestamp)
		binary.Write(hasher, binary.LittleEndian, sth.SHA256RootHash)
	default:
		panic(fmt.Errorf("sthFilename: invalid STH version %d", sth.Version))
	}
	// For 6962-bis, we will need to handle a variable-length root hash, and include the signature in the filename hash (since signatures must be deterministic)
	return strconv.FormatUint(sth.TreeSize, 10) + "-" + base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)) + ".json"
}
