// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package mozilla

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
)

// parseFromURL downloads the CTKnownLogs.h file from the given URL and parses it.
func parseFromURL(url string) ([]CTLogInfo, []CTLogOperatorInfo, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New(resp.Status)
	}
	return Parse(resp.Body)
}

func TestParseFromURL(t *testing.T) {
	logs, ops, err := parseFromURL("https://hg-edge.mozilla.org/mozilla-central/raw-file/tip/security/ct/CTKnownLogs.h")
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) == 0 {
		t.Fatal("no operators parsed")
	}
	foundGoogle := false
	foundSectigo := false
	foundLets := false
	for _, op := range ops {
		if op.Name == "" {
			t.Error("operator with empty name")
		}
		switch op.Name {
		case "Google":
			foundGoogle = true
		case "Sectigo":
			foundSectigo = true
		case "Let's Encrypt":
			foundLets = true
		}
	}
	if !foundGoogle || !foundSectigo || !foundLets {
		t.Errorf("missing expected operators: Google=%v Sectigo=%v Let's=%v", foundGoogle, foundSectigo, foundLets)
	}

	if len(logs) == 0 {
		t.Fatal("no logs parsed")
	}
	foundHash := false
	targetHash := "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc="
	for _, l := range logs {
		if l.Name == "" {
			t.Error("log with empty name")
		}
		if len(l.Key) == 0 {
			t.Error("log with empty key")
		}
		if l.State != "Admissible" && l.State != "Retired" {
			t.Errorf("unexpected state %q", l.State)
		}
		hash := sha256.Sum256(l.Key)
		if base64.StdEncoding.EncodeToString(hash[:]) == targetHash {
			foundHash = true
		}
	}
	if !foundHash {
		t.Errorf("log with key hash %s not found", targetHash)
	}
}
