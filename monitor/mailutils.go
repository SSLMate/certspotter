// Copyright (C) 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"crypto/rand"
	"encoding/hex"
	"os"
)

const mailDateFormat = "Mon, 2 Jan 2006 15:04:05 -0700"

func generateMessageID() string {
	var randomBytes [16]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(randomBytes[:]) + "@selfhosted.certspotter.org"
}

func sendmailPath() string {
	if envVar := os.Getenv("SENDMAIL_PATH"); envVar != "" {
		return envVar
	} else {
		return "/usr/sbin/sendmail"
	}
}
