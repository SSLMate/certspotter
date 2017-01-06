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
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"

	"software.sslmate.com/src/certspotter/ct"
)

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func writeFile(filename string, data []byte, perm os.FileMode) error {
	tempname := filename + ".new"
	if err := ioutil.WriteFile(tempname, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tempname, filename); err != nil {
		os.Remove(tempname)
		return err
	}
	return nil
}

func writeJSONFile(filename string, obj interface{}, perm os.FileMode) error {
	tempname := filename + ".new"
	f, err := os.OpenFile(tempname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(obj); err != nil {
		f.Close()
		os.Remove(tempname)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tempname)
		return err
	}
	if err := os.Rename(tempname, filename); err != nil {
		os.Remove(tempname)
		return err
	}
	return nil
}

func readJSONFile(filename string, obj interface{}) error {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(bytes, obj); err != nil {
		return err
	}
	return nil
}

func readSTHFile(filename string) (*ct.SignedTreeHead, error) {
	sth := new(ct.SignedTreeHead)
	if err := readJSONFile(filename, sth); err != nil {
		return nil, err
	}
	return sth, nil
}

func sha256sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha256hex(data []byte) string {
	return hex.EncodeToString(sha256sum(data))
}
