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
	"fmt"
)

func (list *List) Validate() error {
	for i := range list.Operators {
		if err := list.Operators[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth operator (%s): %w", i, list.Operators[i].Name, err)
		}
	}
	return nil
}

func (operator *Operator) Validate() error {
	for i := range operator.Logs {
		if err := operator.Logs[i].Validate(); err != nil {
			return fmt.Errorf("problem with %dth log (%s): %w", i, operator.Logs[i].LogIDString(), err)
		}
	}
	return nil
}

func (log *Log) Validate() error {
	realLogID := sha256.Sum256(log.Key)
	if log.LogID != realLogID {
		return fmt.Errorf("log ID does not match log key")
	}
	return nil
}
