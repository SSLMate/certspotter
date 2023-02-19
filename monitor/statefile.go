// Copyright (C) 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/merkletree"
	"time"
)

type stateFile struct {
	DownloadPosition *merkletree.CollapsedTree `json:"download_position"`
	VerifiedPosition *merkletree.CollapsedTree `json:"verified_position"`
	VerifiedSTH      *ct.SignedTreeHead        `json:"verified_sth"`
	LastSuccess      time.Time                 `json:"last_success"`
}

func loadStateFile(filePath string) (*stateFile, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	file := new(stateFile)
	if err := json.Unmarshal(fileBytes, file); err != nil {
		return nil, fmt.Errorf("error parsing %s: %w", filePath, err)
	}
	return file, nil
}

func (file *stateFile) store(filePath string) error {
	return writeJSONFile(filePath, file, 0666)
}
