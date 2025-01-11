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
	"context"
	"log"

	"software.sslmate.com/src/certspotter/loglist"
)

func recordError(ctx context.Context, config *Config, ctlog *loglist.Log, errToRecord error) {
	if err := config.State.NotifyError(ctx, ctlog, errToRecord); err != nil {
		log.Print("unable to notify about error: ", err)
		if ctlog == nil {
			log.Print(errToRecord)
		} else {
			log.Print(ctlog.URL, ": ", errToRecord)
		}
	}
}
