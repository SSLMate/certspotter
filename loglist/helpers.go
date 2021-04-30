// Copyright (C) 2020 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package loglist

import (
	"time"
)

func (list *List) AllLogs() []*Log {
	logs := []*Log{}
	for operator := range list.Operators {
		for log := range list.Operators[operator].Logs {
			logs = append(logs, &list.Operators[operator].Logs[log])
		}
	}
	return logs
}

func (log *Log) LogIDString() string {
	return log.LogID.Base64String()
}

func (log *Log) AcceptsExpiration(expiration time.Time) bool {
	return log.TemporalInterval == nil || withinInterval(expiration, log.TemporalInterval.StartInclusive, log.TemporalInterval.EndExclusive)
}

func withinInterval(expiration, startInclusive, endExclusive time.Time) bool {
	return !expiration.Before(startInclusive) && expiration.Before(endExclusive)
}
