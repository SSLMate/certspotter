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
	"fmt"
	"os"
)

func randomFileSuffix() string {
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(randomBytes[:])
}

func writeFile(filename string, data []byte, perm os.FileMode) error {
	tempname := filename + ".tmp." + randomFileSuffix()
	if err := os.WriteFile(tempname, data, perm); err != nil {
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	if err := os.Rename(tempname, filename); err != nil {
		os.Remove(tempname)
		return fmt.Errorf("error writing %s: %w", filename, err)
	}
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
}
