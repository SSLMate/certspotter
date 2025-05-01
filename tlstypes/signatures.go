// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package tlstypes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
)

type HashAlgorithm uint8

const (
	SHA224 HashAlgorithm = 3
	SHA256 HashAlgorithm = 4
	SHA384 HashAlgorithm = 5
	SHA512 HashAlgorithm = 6
)

type SignatureAlgorithm uint8

const (
	RSA   SignatureAlgorithm = 1
	ECDSA SignatureAlgorithm = 3
)

type SignatureAndHashAlgorithm struct {
	Hash      HashAlgorithm
	Signature SignatureAlgorithm
}

type DigitallySigned struct {
	Algorithm SignatureAndHashAlgorithm
	Signature []byte
}

func (v HashAlgorithm) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(v))
	return nil
}
func (v *HashAlgorithm) Unmarshal(s *cryptobyte.String) bool {
	return s.ReadUint8((*uint8)(v))
}

func (v SignatureAlgorithm) Marshal(b *cryptobyte.Builder) error {
	b.AddUint8(uint8(v))
	return nil
}
func (v *SignatureAlgorithm) Unmarshal(s *cryptobyte.String) bool {
	return s.ReadUint8((*uint8)(v))
}

func (v SignatureAndHashAlgorithm) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(v.Hash)
	b.AddValue(v.Signature)
	return nil
}
func (v *SignatureAndHashAlgorithm) Unmarshal(s *cryptobyte.String) bool {
	return v.Hash.Unmarshal(s) && v.Signature.Unmarshal(s)
}

func (v DigitallySigned) Marshal(b *cryptobyte.Builder) error {
	b.AddValue(v.Algorithm)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(v.Signature) })
	return nil
}
func (v *DigitallySigned) Unmarshal(s *cryptobyte.String) bool {
	return v.Algorithm.Unmarshal(s) && s.ReadUint16LengthPrefixed((*cryptobyte.String)(&v.Signature))
}

func (v DigitallySigned) Bytes() []byte {
	b := cryptobyte.NewBuilder(make([]byte, 0, 4+len(v.Signature)))
	b.AddValue(v)
	return b.BytesOrPanic()
}

func (v DigitallySigned) MarshalBinary() ([]byte, error) {
	b := cryptobyte.NewBuilder(make([]byte, 0, 4+len(v.Signature)))
	b.AddValue(v)
	return b.Bytes()
}

func (v *DigitallySigned) UnmarshalBinary(data []byte) error {
	str := cryptobyte.String(bytes.Clone(data))
	if !v.Unmarshal(&str) {
		return fmt.Errorf("DigitallySigned bytes are malformed")
	}
	if !str.Empty() {
		return fmt.Errorf("trailing bytes after DigitallySigned")
	}
	return nil
}

func (v DigitallySigned) MarshalJSON() ([]byte, error) {
	b := cryptobyte.NewBuilder(make([]byte, 0, 4+len(v.Signature)))
	b.AddValue(v)
	if bytes, err := b.Bytes(); err != nil {
		return nil, err
	} else {
		return json.Marshal(bytes)
	}
}
func (v *DigitallySigned) UnmarshalJSON(data []byte) error {
	str := new(cryptobyte.String)
	if err := json.Unmarshal(data, (*[]byte)(str)); err != nil {
		return fmt.Errorf("unable to unmarshal DigitallySigned JSON: %w", err)
	}
	if !v.Unmarshal(str) {
		return fmt.Errorf("DigitallySigned bytes are malformed")
	}
	if !str.Empty() {
		return fmt.Errorf("trailing bytes after DigitallySigned")
	}
	return nil
}
func ParseDigitallySigned(bytes []byte) (*DigitallySigned, error) {
	ds := new(DigitallySigned)
	str := cryptobyte.String(bytes)
	if !ds.Unmarshal(&str) {
		return nil, fmt.Errorf("DigitallySigned bytes are malformed")
	}
	if !str.Empty() {
		return nil, fmt.Errorf("trailing bytes after DigitallySigned")
	}
	return ds, nil
}
