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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
)

func randomFileSuffix() string {
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(randomBytes[:])
}

func writeSyncFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err2 := f.Sync(); err2 != nil && err == nil {
		err = err2
	}
	if err2 := f.Close(); err2 != nil && err == nil {
		err = err2
	}
	return err
}

func writeFile(filename string, data []byte, perm os.FileMode) error {
	tempname := filename + ".tmp." + randomFileSuffix()
	if err := writeSyncFile(tempname, data, perm); err != nil {
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	if err := os.Rename(tempname, filename); err != nil {
		os.Remove(tempname)
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	return nil
}

func writeTextFile(filename string, fileText string, perm os.FileMode) error {
	return writeFile(filename, []byte(fileText), perm)
}

func writeJSONFile(filename string, data any, perm os.FileMode) error {
	fileBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	fileBytes = append(fileBytes, '\n')
	return writeFile(filename, fileBytes, perm)
}

func fileExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
}

func tailFile(filename string, linesWanted int) ([]byte, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	return tail(file, linesWanted, 4096)
}

func tail(r io.ReadSeeker, linesWanted int, chunkSize int) ([]byte, int, error) {
	var buf []byte
	linesGot := 0

	offset, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, 0, err
	}
	for offset > 0 {
		readSize := chunkSize
		if offset < int64(readSize) {
			readSize = int(offset)
		}
		offset -= int64(readSize)
		if _, err := r.Seek(offset, io.SeekStart); err != nil {
			return nil, 0, err
		}
		buf = slices.Grow(buf, readSize)
		copy(buf[readSize:len(buf)+readSize], buf)
		buf = buf[:len(buf)+readSize]
		if _, err := io.ReadFull(r, buf[:readSize]); err != nil {
			return nil, 0, err
		}
		for i := readSize; i > 0; i-- {
			if buf[i-1] == '\n' {
				if linesGot == linesWanted {
					return buf[i:], linesGot, nil
				}
				linesGot++
			}
		}
	}
	return buf, linesGot, nil
}
