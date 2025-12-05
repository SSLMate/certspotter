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

	"software.sslmate.com/src/certspotter/cttypes"
)

type List struct {
	Version          string     `json:"version,omitzero"`
	LogListTimestamp time.Time  `json:"log_list_timestamp,omitzero"` // Only present in v3 of schema
	Operators        []Operator `json:"operators,omitzero"`
}

type Operator struct {
	Name      string   `json:"name"`
	Email     []string `json:"email,omitzero"`
	Logs      []Log    `json:"logs,omitzero"`
	TiledLogs []Log    `json:"tiled_logs,omitzero"`
}

type Log struct {
	Key              []byte        `json:"key"`
	LogID            cttypes.LogID `json:"log_id"`
	MMD              int           `json:"mmd"`
	URL              string        `json:"url,omitzero"`            // only for rfc6962 logs
	SubmissionURL    string        `json:"submission_url,omitzero"` // only for static-ct-api logs
	MonitoringURL    string        `json:"monitoring_url,omitzero"` // only for static-ct-api logs
	Description      string        `json:"description"`
	State            State         `json:"state,omitzero"`
	LogType          LogType       `json:"log_type,omitzero"`
	TemporalInterval *struct {
		StartInclusive time.Time `json:"start_inclusive"`
		EndExclusive   time.Time `json:"end_exclusive"`
	} `json:"temporal_interval,omitzero"`

	// certspotter-specific extensions
	CertspotterDownloadSize int     `json:"certspotter_download_size,omitzero"`
	CertspotterDownloadJobs int     `json:"certspotter_download_jobs,omitzero"`
	CertspotterDownloadQPS  float64 `json:"certspotter_download_qps,omitzero"`

	// TODO: add previous_operators
}

func (log *Log) IsRFC6962() bool     { return log.URL != "" }
func (log *Log) IsStaticCTAPI() bool { return log.SubmissionURL != "" && log.MonitoringURL != "" }

// Return URL prefix for submission using the RFC6962 protocol
func (log *Log) GetSubmissionURL() string {
	if log.SubmissionURL != "" {
		return log.SubmissionURL
	} else {
		return log.URL
	}
}

// Return URL prefix for monitoring.
// Since the protocol understood by the URL might be either RFC6962 or static-ct-api, this URL is
// only useful for informational purposes.
func (log *Log) GetMonitoringURL() string {
	if log.MonitoringURL != "" {
		return log.MonitoringURL
	} else {
		return log.URL
	}
}

type State struct {
	Pending *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"pending,omitzero"`

	Qualified *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"qualified,omitzero"`

	Usable *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"usable,omitzero"`

	Readonly *struct {
		Timestamp     time.Time `json:"timestamp"`
		FinalTreeHead struct {
			TreeSize       int64  `json:"tree_size"`
			SHA256RootHash []byte `json:"sha256_root_hash"`
		} `json:"final_tree_head"`
	} `json:"readonly,omitzero"`

	Retired *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"retired,omitzero"`

	Rejected *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"rejected,omitzero"`
}

func (state *State) IsApproved() bool {
	return state.Qualified != nil || state.Usable != nil || state.Readonly != nil
}

func (state *State) WasApprovedAt(t time.Time) bool {
	return state.Retired != nil && t.Before(state.Retired.Timestamp)
}

type LogType string

const (
	LogTypeProd = "prod"
	LogTypeTest = "test"
)
