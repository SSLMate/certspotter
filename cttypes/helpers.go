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
	"golang.org/x/crypto/cryptobyte"
)

func addBytesFunc(v []byte) cryptobyte.BuilderContinuation {
	return func(b *cryptobyte.Builder) {
		b.AddBytes(v)
	}
}
