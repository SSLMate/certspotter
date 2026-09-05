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

func (list *List) Normalize() error {
	for i := range list.Operators {
		if err := list.Operators[i].Normalize(); err != nil {
			return fmt.Errorf("problem with %dth operator (%s): %w", i, list.Operators[i].Name, err)
		}
	}
	return nil
}

func (operator *Operator) Normalize() error {
	for i := range operator.Logs {
		if err := operator.Logs[i].Normalize(); err != nil {
			return fmt.Errorf("problem with %dth non-tiled log (%s): %w", i, operator.Logs[i].LogIDString(), err)
		}
	}
	for i := range operator.TiledLogs {
		if err := operator.TiledLogs[i].Normalize(); err != nil {
			return fmt.Errorf("problem with %dth tiled log (%s): %w", i, operator.TiledLogs[i].LogIDString(), err)
		}
	}
	return nil
}

// Normalize validates and normalizes the log, ensuring that the resulting JSON object can
// be parsed by both a v3 log list parser, and a v2 log object parser.
func (log *Log) Normalize() error {
	realLogID := sha256.Sum256(log.Key)
	if log.LogID != realLogID {
		return fmt.Errorf("log ID does not match log key")
	}

	if log.URL == "" {
		log.URL = log.Endpoint.URL
	} else if log.Endpoint.URL == "" {
		log.Endpoint.URL = log.URL
	}
	if log.URL != log.Endpoint.URL {
		return fmt.Errorf("inconsistent URLs provided (%q vs %q)", log.URL, log.Endpoint.URL)
	}

	if log.MonitoringURL == "" {
		log.MonitoringURL = log.MonitoringEndpoint.URL
	} else if log.MonitoringEndpoint.URL == "" {
		log.MonitoringEndpoint.URL = log.MonitoringURL
	}
	if log.MonitoringURL != log.MonitoringEndpoint.URL {
		return fmt.Errorf("inconsistent monitoring URLs provided (%q vs %q)", log.MonitoringURL, log.MonitoringEndpoint.URL)
	}

	if log.SubmissionURL == "" {
		log.SubmissionURL = log.SubmissionEndpoint.URL
	} else if log.SubmissionEndpoint.URL == "" {
		log.SubmissionEndpoint.URL = log.SubmissionURL
	}
	if log.SubmissionURL != log.SubmissionEndpoint.URL {
		return fmt.Errorf("inconsistent submission URLs provided (%q vs %q)", log.SubmissionURL, log.SubmissionEndpoint.URL)
	}

	if !log.IsRFC6962() && !log.IsStaticCTAPI() {
		return fmt.Errorf("URL(s) not provided")
	} else if log.IsRFC6962() && log.IsStaticCTAPI() {
		return fmt.Errorf("inconsistent URLs provided")
	}

	log.MMD = max(log.MMD, log.MMDSeconds)
	log.MMDSeconds = log.MMD

	if log.MMD < 0 {
		return fmt.Errorf("log has a negative MMD")
	}

	return nil
}
