// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package loglist

import _ "embed"

// ChromePubkey is the DER-encoded PKIX public key which Google uses to sign
// Chrome's CT log lists.
//
// The key was downloaded from https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem
// as documented at https://googlechrome.github.io/CertificateTransparency/log_lists.html.
//
//go:embed chrome_pubkey.der
var ChromePubkey []byte
