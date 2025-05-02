// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package cttypes

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

type LogID [32]byte

func (v *LogID) Unmarshal(s *cryptobyte.String) bool {
	return s.CopyBytes((*v)[:])
}
func (v LogID) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(v[:])
	return nil
}

func (id *LogID) UnmarshalBinary(bytes []byte) error {
	if len(bytes) != len(*id) {
		return fmt.Errorf("LogID has wrong length (should be %d, not %d)", len(*id), len(bytes))
	}
	*id = (LogID)(bytes)
	return nil
}
func (id LogID) MarshalBinary() ([]byte, error) {
	return id[:], nil
}

func (id *LogID) UnmarshalText(textData []byte) error {
	if len(textData) != 44 {
		return fmt.Errorf("LogID has wrong length (should be %d, not %d)", 44, len(textData))
	}
	var bytes [33]byte
	if n, err := base64.StdEncoding.Decode(bytes[:], textData); err != nil {
		return fmt.Errorf("LogID contains invalid base64: %w", err)
	} else if n != 32 {
		return fmt.Errorf("LogID has wrong length (should be %d bytes, not %d)", 32, n)
	}
	copy(id[:], bytes[:])
	return nil
}
func (id LogID) MarshalText() ([]byte, error) {
	encodedBytes := make([]byte, 44)
	base64.StdEncoding.Encode(encodedBytes, id[:])
	return encodedBytes, nil
}

func (id LogID) Base64String() string {
	return base64.StdEncoding.EncodeToString(id[:])
}

func (id LogID) Base64URLString() string {
	return base64.RawURLEncoding.EncodeToString(id[:])
}
