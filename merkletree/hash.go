// Copyright (C) 2022 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const HashLen = 32

type Hash [HashLen]byte

func (h Hash) Compare(other Hash) int {
	return bytes.Compare(h[:], other[:])
}

func (h Hash) Base64String() string {
	return base64.StdEncoding.EncodeToString(h[:])
}

func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h[:])
}

func (h Hash) MarshalBinary() ([]byte, error) {
	return h[:], nil
}

func (h *Hash) UnmarshalJSON(b []byte) error {
	var hashBytes []byte
	if err := json.Unmarshal(b, &hashBytes); err != nil {
		return err
	}
	return h.UnmarshalBinary(hashBytes)
}

func (h *Hash) UnmarshalBinary(hashBytes []byte) error {
	if len(hashBytes) != HashLen {
		return fmt.Errorf("Merkle Tree hash has wrong length (should be %d bytes long, not %d)", HashLen, len(hashBytes))
	}
	copy(h[:], hashBytes)
	return nil
}

func HashNothing() Hash {
	return sha256.Sum256(nil)
}

func HashLeaf(leafBytes []byte) Hash {
	var hash Hash
	hasher := sha256.New()
	hasher.Write([]byte{0x00})
	hasher.Write(leafBytes)
	hasher.Sum(hash[:0])
	return hash
}

func HashChildren(left Hash, right Hash) Hash {
	var hash Hash
	hasher := sha256.New()
	hasher.Write([]byte{0x01})
	hasher.Write(left[:])
	hasher.Write(right[:])
	hasher.Sum(hash[:0])
	return hash
}
