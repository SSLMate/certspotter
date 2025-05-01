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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"software.sslmate.com/src/certspotter/merkletree"
	"software.sslmate.com/src/certspotter/tlstypes"
)

func chompLine(input []byte) (string, []byte, bool) {
	newline := bytes.IndexByte(input, '\n')
	if newline == -1 {
		return "", nil, false
	}
	return string(input[:newline]), input[newline+1:], true
}

func makeCheckpointKeyID(origin string, logID LogID) [4]byte {
	h := sha256.New()
	h.Write([]byte(origin))
	h.Write([]byte{'\n', 0x05})
	h.Write(logID[:])

	var digest [sha256.Size]byte
	h.Sum(digest[:0])
	return [4]byte(digest[:4])
}

func ParseCheckpoint(input []byte, logID LogID) (*SignedTreeHead, error) {
	// origin
	origin, input, _ := chompLine(input)

	// tree size
	sizeLine, input, _ := chompLine(input)
	treeSize, err := strconv.ParseUint(sizeLine, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed tree size: %w", err)
	}

	// root hash
	hashLine, input, _ := chompLine(input)
	rootHash, err := base64.StdEncoding.DecodeString(hashLine)
	if err != nil {
		return nil, fmt.Errorf("malformed root hash: %w", err)
	}
	if len(rootHash) != merkletree.HashLen {
		return nil, fmt.Errorf("root hash has wrong length (should be %d bytes long, not %d)", merkletree.HashLen, len(rootHash))
	}

	// 0 or more non-empty extension lines (ignored)
	for {
		line, rest, ok := chompLine(input)
		if !ok {
			return nil, errors.New("signed note ended prematurely")
		}
		input = rest
		if len(line) == 0 {
			break
		}
	}

	// signature lines
	signaturePrefix := "\u2014 " + origin + " "
	keyID := makeCheckpointKeyID(origin, logID)
	for {
		signatureLine, rest, ok := chompLine(input)
		if !ok {
			return nil, errors.New("signed note is missing signature from the log")
		}
		input = rest
		if !strings.HasPrefix(signatureLine, signaturePrefix) {
			continue
		}
		signatureBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(signatureLine, signaturePrefix))
		if err != nil {
			return nil, fmt.Errorf("malformed signature: %w", err)
		}
		if !bytes.HasPrefix(signatureBytes, keyID[:]) {
			continue
		}
		if len(signatureBytes) < 12 {
			return nil, errors.New("malformed signature: too short")
		}
		timestamp := binary.BigEndian.Uint64(signatureBytes[4:12])
		signature, err := tlstypes.ParseDigitallySigned(signatureBytes[12:])
		if err != nil {
			return nil, fmt.Errorf("malformed signature: %w", err)
		}
		return &SignedTreeHead{
			TreeSize:  treeSize,
			Timestamp: timestamp,
			RootHash:  (merkletree.Hash)(rootHash),
			Signature: *signature,
		}, nil
	}
}
