// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package ctcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"software.sslmate.com/src/certspotter/tlstypes"
)

type PublicKey []byte

func (key PublicKey) Verify(input SignatureInput, signature tlstypes.DigitallySigned) error {
	parsedKey, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("error parsing log key: %w", err)
	}
	switch key := parsedKey.(type) {
	case *rsa.PublicKey:
		if signature.Algorithm.Signature != tlstypes.RSA {
			return fmt.Errorf("log key is RSA but this is not an RSA signature")
		}
		if signature.Algorithm.Hash != tlstypes.SHA256 {
			return fmt.Errorf("unsupported hash algorithm %v (only SHA-256 is allowed in CT)", signature.Algorithm.Hash)
		}
		if rsa.VerifyPKCS1v15((*rsa.PublicKey)(key), crypto.SHA256, input[:], signature.Signature) != nil {
			return fmt.Errorf("RSA signature is incorrect")
		}
		return nil

	case *ecdsa.PublicKey:
		if signature.Algorithm.Signature != tlstypes.ECDSA {
			return fmt.Errorf("log key is ECDSA but this is not an ECDSA signature")
		}
		if signature.Algorithm.Hash != tlstypes.SHA256 {
			return fmt.Errorf("unsupported hash algorithm %v (only SHA-256 is allowed in CT)", signature.Algorithm.Hash)
		}
		if !ecdsa.VerifyASN1((*ecdsa.PublicKey)(key), input[:], signature.Signature) {
			return fmt.Errorf("ECDSA signature is incorrect")
		}

	default:
		return fmt.Errorf("unsupported public key type %T (CT only allows RSA and ECDSA)", key)
	}
	return nil
}

func (key PublicKey) MarshalBinary() ([]byte, error) {
	return bytes.Clone(key), nil
}

func (key *PublicKey) UnmarshalBinary(data []byte) error {
	*key = bytes.Clone(data)
	return nil
}
