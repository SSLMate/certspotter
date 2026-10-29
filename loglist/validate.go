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
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// maxSignedListAge is the maximum age of a signed log list, as determined
// by its log_list_timestamp.
const maxSignedListAge = 48 * time.Hour

func (list *List) Validate() error {
	for i := range list.Operators {
		if err := list.Operators[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth operator (%s): %w", i, list.Operators[i].Name, err)
		}
	}
	return nil
}

func (list *List) validateSigned(name string, now time.Time) error {
	if list.LogListName != "" && list.LogListName != name {
		return fmt.Errorf("log_list_name is %q, want %q", list.LogListName, name)
	}
	if list.LogListTimestamp.IsZero() {
		return errors.New("log_list_timestamp is missing")
	}
	if age := now.Sub(list.LogListTimestamp); age > maxSignedListAge {
		return fmt.Errorf("log_list_timestamp (%s) is more than %v in the past", list.LogListTimestamp.Format(time.RFC3339), maxSignedListAge)
	}
	return nil
}

func (operator *Operator) Validate() error {
	for i := range operator.Logs {
		if err := operator.Logs[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth non-tiled log (%s): %w", i, operator.Logs[i].LogIDString(), err)
		}
	}
	for i := range operator.TiledLogs {
		if err := operator.TiledLogs[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth tiled log (%s): %w", i, operator.TiledLogs[i].LogIDString(), err)
		}
	}
	return nil
}

func (log *Log) Validate() error {
	realLogID := sha256.Sum256(log.Key)
	if log.LogID != realLogID {
		return fmt.Errorf("log ID does not match log key")
	}

	if !log.IsRFC6962() && !log.IsStaticCTAPI() {
		return fmt.Errorf("URL(s) not provided")
	} else if log.IsRFC6962() && log.IsStaticCTAPI() {
		return fmt.Errorf("inconsistent URLs provided")
	}

	if log.MMD < 0 {
		return fmt.Errorf("log has a negative MMD")
	}

	return nil
}
