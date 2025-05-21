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
	"software.sslmate.com/src/certspotter/merkletree"
	"software.sslmate.com/src/certspotter/tlstypes"
	"time"
)

type SignedTreeHead struct {
	TreeSize  uint64                   `json:"tree_size"`
	Timestamp uint64                   `json:"timestamp"`
	RootHash  merkletree.Hash          `json:"sha256_root_hash"`
	Signature tlstypes.DigitallySigned `json:"tree_head_signature"`
}

type GossipedSignedTreeHead struct {
	SignedTreeHead
	STHVersion Version `json:"sth_version"`
	LogID      LogID   `json:"log_id"`
}

func (sth *SignedTreeHead) TimestampTime() time.Time {
	return time.UnixMilli(int64(sth.Timestamp))
}

func (sth *SignedTreeHead) Same(other *SignedTreeHead) bool {
	return sth.TreeSize == other.TreeSize && sth.Timestamp == other.Timestamp && sth.RootHash == other.RootHash
}
