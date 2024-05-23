// Copyright (C) 2016, 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"bufio"
	"encoding/hex"
	"crypto/sha256"
	"fmt"
	"io"
	"software.sslmate.com/src/certspotter"
	"strings"
)

type KeyItem struct {
	domain       string
	keyinfo      string
}

type KeyList []KeyItem

func ParseKeyItem(str string) (KeyItem, error) {
	fields := strings.Split(str, ";")
	if len(fields) == 0 {
		return KeyItem{}, fmt.Errorf("empty domain")
	}
	if len(fields) == 1 {
		return KeyItem{}, fmt.Errorf("empty key info")
	}
	return KeyItem{
		domain:       fields[0],
		keyinfo:      fields[1],
	}, nil
}

func ReadKeyList(reader io.Reader) (KeyList, error) {
	items := make(KeyList, 0, 50)
	scanner := bufio.NewScanner(reader)
	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		item, err := ParseKeyItem(line)
		if err != nil {
			return nil, fmt.Errorf("%w on line %d", err, lineNo)
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}

func (item KeyItem) String() string {
	return item.domain
}

func (list KeyList) Matches(certInfo *certspotter.CertInfo) (bool, KeyItem) {
     
	for _, item := range list {
	        // better would be to convert the input and compare the bytes (no uppercase/lower-case issue)
	        pub := sha256.Sum256(certInfo.TBS.PublicKey.FullBytes)
		sum := hex.EncodeToString(pub[:])
		if sum == item.keyinfo {
			return true, item
		}
	}
	return false, KeyItem{}
}
