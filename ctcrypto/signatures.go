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
	"crypto/sha256"
	"golang.org/x/crypto/cryptobyte"

	"software.sslmate.com/src/certspotter/cttypes"
)

type SignatureInput [32]byte

func MakeSignatureInput(message []byte) SignatureInput {
	return sha256.Sum256(message)
}

func SignatureInputForPrecertSCT(sct *cttypes.SignedCertificateTimestamp, precert cttypes.PreCert) SignatureInput {
	var builder cryptobyte.Builder
	builder.AddValue(sct.SCTVersion)
	builder.AddValue(cttypes.CertificateTimestampSignatureType)
	builder.AddUint64(sct.Timestamp)
	builder.AddValue(cttypes.PrecertEntryType)
	builder.AddValue(&precert)
	builder.AddValue(sct.Extensions)
	return MakeSignatureInput(builder.BytesOrPanic())
}

func SignatureInputForCertSCT(sct *cttypes.SignedCertificateTimestamp, cert cttypes.ASN1Cert) SignatureInput {
	var builder cryptobyte.Builder
	builder.AddValue(sct.SCTVersion)
	builder.AddValue(cttypes.CertificateTimestampSignatureType)
	builder.AddUint64(sct.Timestamp)
	builder.AddValue(cttypes.X509EntryType)
	builder.AddValue(cert)
	builder.AddValue(sct.Extensions)
	return MakeSignatureInput(builder.BytesOrPanic())
}

func SignatureInputForSTH(sth *cttypes.SignedTreeHead) SignatureInput {
	var builder cryptobyte.Builder
	builder.AddValue(cttypes.V1)
	builder.AddValue(cttypes.TreeHashSignatureType)
	builder.AddUint64(sth.Timestamp)
	builder.AddUint64(sth.TreeSize)
	builder.AddBytes(sth.RootHash[:])
	return MakeSignatureInput(builder.BytesOrPanic())
}
