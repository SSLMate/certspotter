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
)

type TBSCertificate []byte

type ASN1Cert []byte

type ASN1CertChain []ASN1Cert

// Corresponds to the PreCert structure in RFC 6962.  PreCert is a misnomer because this is really a TBSCertificate, not a precertificate.
type PreCert struct {
	IssuerKeyHash  [32]byte
	TBSCertificate TBSCertificate
}

type PrecertChainEntry struct {
	PreCertificate      ASN1Cert
	PrecertificateChain ASN1CertChain
}

func (v *TBSCertificate) Unmarshal(s *cryptobyte.String) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(v))
}
func (v TBSCertificate) Marshal(b *cryptobyte.Builder) error {
	b.AddUint24LengthPrefixed(addBytesFunc(v))
	return nil
}

func (v *ASN1Cert) Unmarshal(s *cryptobyte.String) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(v))
}
func (v ASN1Cert) Marshal(b *cryptobyte.Builder) error {
	b.AddUint24LengthPrefixed(addBytesFunc(v))
	return nil
}

func (v *ASN1CertChain) Unmarshal(s *cryptobyte.String) bool {
	chainBytes := new(cryptobyte.String)
	if !s.ReadUint24LengthPrefixed(chainBytes) {
		return false
	}
	*v = []ASN1Cert{}
	for !chainBytes.Empty() {
		var cert ASN1Cert
		if !cert.Unmarshal(chainBytes) {
			return false
		}
		*v = append(*v, cert)
	}
	return true
}
func (v ASN1CertChain) Marshal(b *cryptobyte.Builder) error {
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, cert := range v {
			b.AddValue(cert)
		}
	})
	return nil
}

func (precert *PreCert) Unmarshal(s *cryptobyte.String) error {
	if !s.CopyBytes(precert.IssuerKeyHash[:]) {
		return fmt.Errorf("error reading PreCert issuer_key_hash")
	}
	if !precert.TBSCertificate.Unmarshal(s) {
		return fmt.Errorf("error reading PreCert tbs_certificate")
	}
	return nil
}
func (v *PreCert) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(v.IssuerKeyHash[:])
	b.AddValue(v.TBSCertificate)
	return nil
}

func (entry *PrecertChainEntry) Unmarshal(s *cryptobyte.String) error {
	if !entry.PreCertificate.Unmarshal(s) {
		return fmt.Errorf("error reading PrecertChainEntry pre_certificate")
	}
	if !entry.PrecertificateChain.Unmarshal(s) {
		return fmt.Errorf("error reading PrecertChainEntry preeertificate_chain")
	}
	return nil
}

func ParseExtraDataForX509Entry(extraData []byte) (ASN1CertChain, error) {
	str := cryptobyte.String(extraData)
	var chain ASN1CertChain
	if !chain.Unmarshal(&str) {
		return nil, fmt.Errorf("error reading ASN.1Cert chain")
	}
	if !str.Empty() {
		return nil, fmt.Errorf("trailing garbage after ASN.1Cert chain")
	}
	return chain, nil
}

func ParseExtraDataForPrecertEntry(extraData []byte) (*PrecertChainEntry, error) {
	str := cryptobyte.String(extraData)
	entry := new(PrecertChainEntry)
	if err := entry.Unmarshal(&str); err != nil {
		return nil, err
	}
	if !str.Empty() {
		return nil, fmt.Errorf("trailing garbage after PrecertChainEntry")
	}
	return entry, nil
}
