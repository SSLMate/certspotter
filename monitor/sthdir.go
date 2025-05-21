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
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"software.sslmate.com/src/certspotter/cttypes"
	"strconv"
	"strings"
	"time"
)

type StoredSTH struct {
	cttypes.SignedTreeHead
	StoredAt time.Time `json:"stored_at"` // time at which the STH was first stored
}

func loadSTHsFromDir(dirPath string) ([]*StoredSTH, error) {
	entries, err := os.ReadDir(dirPath)
	if errors.Is(err, fs.ErrNotExist) {
		return []*StoredSTH{}, nil
	} else if err != nil {
		return nil, err
	}
	sths := make([]*StoredSTH, 0, len(entries))
	for _, entry := range entries {
		filename := entry.Name()
		if strings.HasPrefix(filename, ".") || !strings.HasSuffix(filename, ".json") {
			continue
		}
		sth, err := readSTHFile(filepath.Join(dirPath, filename))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		sths = append(sths, sth)
	}
	slices.SortFunc(sths, func(a, b *StoredSTH) int { return cmp.Compare(a.TreeSize, b.TreeSize) })
	return sths, nil
}

func readSTHFile(filePath string) (*StoredSTH, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	sth := &StoredSTH{
		StoredAt: info.ModTime(),
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %w", filePath, err)
	}
	if err := json.Unmarshal(fileBytes, &sth.SignedTreeHead); err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", filePath, err)
	}
	return sth, nil
}

func storeSTHInDir(dirPath string, sth *cttypes.SignedTreeHead) (*StoredSTH, error) {
	filePath := filepath.Join(dirPath, sthFilename(sth))

	if info, err := os.Lstat(filePath); err == nil {
		return &StoredSTH{
			SignedTreeHead: *sth,
			StoredAt:       info.ModTime(),
		}, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	if err := writeJSONFile(filePath, sth, 0666); err != nil {
		return nil, err
	}

	return &StoredSTH{
		SignedTreeHead: *sth,
		StoredAt:       time.Now(), // not the exact modtime of the file, but close enough for our purposes
	}, nil
}

func removeSTHFromDir(dirPath string, sth *cttypes.SignedTreeHead) error {
	filePath := filepath.Join(dirPath, sthFilename(sth))
	err := os.Remove(filePath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// generate a filename that uniquely identifies the STH (within the context of a particular log)
func sthFilename(sth *cttypes.SignedTreeHead) string {
	hasher := sha256.New()
	binary.Write(hasher, binary.LittleEndian, sth.Timestamp)
	hasher.Write(sth.RootHash[:])
	return strconv.FormatUint(sth.TreeSize, 10) + "-" + base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)) + ".json"
}
