// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package ctclient

import (
	"context"

	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/merkletree"
)

type WritableLog interface {
	AddChain(context.Context, [][]byte) (*cttypes.SignedCertificateTimestamp, error)
	AddPreChain(context.Context, [][]byte) (*cttypes.SignedCertificateTimestamp, error)
	GetRoots(context.Context) ([][]byte, error)
}

type Log interface {
	GetSTH(context.Context) (*cttypes.SignedTreeHead, string, error)
	GetRoots(context.Context) ([][]byte, error)
	GetEntries(ctx context.Context, startInclusive, endInclusive uint64) ([]Entry, error)
	ReconstructTree(context.Context, *cttypes.SignedTreeHead) (*merkletree.CollapsedTree, error)
}

// IssuerGetter represents a source of issuer certificates.
//
// If a [Log] also implements IssuerGetter, then it is mandatory to provide
// an IssuerGetter when using [Entry]s returned by the [Log].  The IssuerGetter
// may be the Log itself, or your own implementation which retrieves issuers
// from a different source, such as a cache.
//
// If a Log doesn't implement IssuerGetter, then you may pass a nil IssuerGetter
// when using the Log's Entrys.
type IssuerGetter interface {
	GetIssuer(ctx context.Context, fingerprint *[32]byte) ([]byte, error)
}

type Entry interface {
	LeafInput() []byte

	// Returns error from IssuerGetter, otherwise infallible
	ExtraData(context.Context, IssuerGetter) ([]byte, error)

	// Returns an error if this is not a well-formed precert entry
	Precertificate() (cttypes.ASN1Cert, error)

	// Returns an error if this is not a well-formed x509 or precert entry
	ChainFingerprints() ([][32]byte, error)

	// Returns an error if this is not a well-formed x509 or precert entry, or if IssuerGetter failed
	GetChain(context.Context, IssuerGetter) (cttypes.ASN1CertChain, error)
}
