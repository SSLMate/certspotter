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
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"software.sslmate.com/src/certspotter/merkletree"
)

type MerkleLeafType uint8

const (
	TimestampedEntryType MerkleLeafType = 0
)

type LogEntryType uint16

const (
	X509EntryType    LogEntryType = 0
	PrecertEntryType LogEntryType = 1
)

type CTExtensions []byte

type MerkleTreeLeaf struct {
	Version          Version
	LeafType         MerkleLeafType
	TimestampedEntry *TimestampedEntry
}

type TimestampedEntry struct {
	Timestamp           uint64
	EntryType           LogEntryType
	SignedEntryASN1Cert *ASN1Cert
	SignedEntryPreCert  *PreCert
	Extensions          CTExtensions
}

func (v *MerkleLeafType) Unmarshal(s *cryptobyte.String) bool {
	return s.ReadUint8((*uint8)(v))
}
func (v MerkleLeafType) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(v))
	return nil
}

func (v *LogEntryType) Unmarshal(s *cryptobyte.String) bool {
	return s.ReadUint16((*uint16)(v))
}
func (v LogEntryType) Marshal(b *cryptobyte.Builder) error {
	b.AddUint16(uint16(v))
	return nil
}

func (v *CTExtensions) Unmarshal(s *cryptobyte.String) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(v))
}
func (v CTExtensions) Marshal(b *cryptobyte.Builder) error {
	b.AddUint16LengthPrefixed(addBytesFunc(v))
	return nil
}

func (leaf *MerkleTreeLeaf) Unmarshal(s *cryptobyte.String) error {
	if !leaf.Version.Unmarshal(s) {
		return fmt.Errorf("error reading MerkleTreeLeaf version")
	}
	if leaf.Version != V1 {
		return fmt.Errorf("unsupported Version 0x%02x", leaf.Version)
	}
	if !leaf.LeafType.Unmarshal(s) {
		return fmt.Errorf("error reading MerkleTreeLeaf leaf_type")
	}
	switch leaf.LeafType {
	case TimestampedEntryType:
		leaf.TimestampedEntry = new(TimestampedEntry)
		if err := leaf.TimestampedEntry.Unmarshal(s); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unrecognized MerkleLeafType 0x%02x", leaf.LeafType)
	}
	return nil
}
func (v *MerkleTreeLeaf) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(v.Version)
	b.AddValue(v.LeafType)
	switch v.LeafType {
	case TimestampedEntryType:
		b.AddValue(v.TimestampedEntry)
	}
	return nil
}
func (v *MerkleTreeLeaf) Bytes() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddValue(v)
	return builder.Bytes()
}
func (v *MerkleTreeLeaf) Hash() merkletree.Hash {
	var builder cryptobyte.Builder
	builder.AddValue(v)
	return merkletree.HashLeaf(builder.BytesOrPanic())
}

func (entry *TimestampedEntry) Unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint64(&entry.Timestamp) {
		return fmt.Errorf("error reading TimestampedEntry timestamp")
	}
	if !entry.EntryType.Unmarshal(s) {
		return fmt.Errorf("error reading TimestampedEntry entry_type")
	}
	switch entry.EntryType {
	case X509EntryType:
		entry.SignedEntryASN1Cert = new(ASN1Cert)
		if !entry.SignedEntryASN1Cert.Unmarshal(s) {
			return fmt.Errorf("error reading TimestampedEntry signed_entry ASN.1Cert")
		}
	case PrecertEntryType:
		entry.SignedEntryPreCert = new(PreCert)
		if err := entry.SignedEntryPreCert.Unmarshal(s); err != nil {
			return fmt.Errorf("error reading TimestampedEntryType signed_entry: %w", err)
		}
	default:
		return fmt.Errorf("unrecognized TimestampedEntryType 0x%02x", entry.EntryType)
	}
	if !entry.Extensions.Unmarshal(s) {
		return fmt.Errorf("error reading TimestampedEntry extensions")
	}
	return nil
}
func (v *TimestampedEntry) Marshal(b *cryptobyte.Builder) error {
	b.AddUint64(v.Timestamp)
	b.AddValue(v.EntryType)
	switch v.EntryType {
	case X509EntryType:
		b.AddValue(v.SignedEntryASN1Cert)
	case PrecertEntryType:
		b.AddValue(v.SignedEntryPreCert)
	}
	b.AddValue(v.Extensions)
	return nil
}

func ParseLeafInput(leafInput []byte) (*MerkleTreeLeaf, error) {
	str := cryptobyte.String(leafInput)
	leaf := new(MerkleTreeLeaf)
	if err := leaf.Unmarshal(&str); err != nil {
		return nil, err
	}
	if !str.Empty() {
		return nil, fmt.Errorf("trailing garbage after MerkleTreeLeaf")
	}
	return leaf, nil
}

func MerkleTreeLeafForCert(timestamp uint64, extensions []byte, cert ASN1Cert) *MerkleTreeLeaf {
	return &MerkleTreeLeaf{
		Version:  V1,
		LeafType: TimestampedEntryType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp:           timestamp,
			EntryType:           X509EntryType,
			SignedEntryASN1Cert: &cert,
			Extensions:          extensions,
		},
	}
}

func MerkleTreeLeafForCertSCT(sct *SignedCertificateTimestamp, cert ASN1Cert) *MerkleTreeLeaf {
	return &MerkleTreeLeaf{
		Version:  sct.SCTVersion,
		LeafType: TimestampedEntryType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp:           sct.Timestamp,
			EntryType:           X509EntryType,
			SignedEntryASN1Cert: &cert,
			Extensions:          sct.Extensions,
		},
	}
}

func MerkleTreeLeafForPrecert(timestamp uint64, extensions []byte, precert PreCert) *MerkleTreeLeaf {
	return &MerkleTreeLeaf{
		Version:  V1,
		LeafType: TimestampedEntryType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp:          timestamp,
			EntryType:          PrecertEntryType,
			SignedEntryPreCert: &precert,
			Extensions:         extensions,
		},
	}
}

func MerkleTreeLeafForPrecertSCT(sct *SignedCertificateTimestamp, precert PreCert) *MerkleTreeLeaf {
	return &MerkleTreeLeaf{
		Version:  sct.SCTVersion,
		LeafType: TimestampedEntryType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp:          sct.Timestamp,
			EntryType:          PrecertEntryType,
			SignedEntryPreCert: &precert,
			Extensions:         sct.Extensions,
		},
	}
}
