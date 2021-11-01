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

	"software.sslmate.com/src/certspotter/ct"
)

type List struct {
	Version          string     `json:"version"`
	LogListTimestamp time.Time  `json:"log_list_timestamp"` // Only present in v3 of schema
	Operators        []Operator `json:"operators"`
}

type Operator struct {
	Name  string   `json:"name"`
	Email []string `json:"email"`
	Logs  []Log    `json:"logs"`
}

type Log struct {
	Key              []byte        `json:"key"`
	LogID            ct.SHA256Hash `json:"log_id"`
	MMD              int           `json:"mmd"`
	URL              string        `json:"url"`
	Description      string        `json:"description"`
	State            State         `json:"state"`
	DNS              string        `json:"dns"`
	LogType          LogType       `json:"log_type"`
	TemporalInterval *struct {
		StartInclusive time.Time `json:"start_inclusive"`
		EndExclusive   time.Time `json:"end_exclusive"`
	} `json:"temporal_interval"`

	// TODO: add previous_operators
}

type State struct {
	Pending *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"pending"`

	Qualified *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"qualified"`

	Usable *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"usable"`

	Readonly *struct {
		Timestamp     time.Time `json:"timestamp"`
		FinalTreeHead struct {
			TreeSize       int64  `json:"tree_size"`
			SHA256RootHash []byte `json:"sha256_root_hash"`
		} `json:"final_tree_head"`
	} `json:"readonly"`

	Retired *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"retired"`

	Rejected *struct {
		Timestamp time.Time `json:"timestamp"`
	} `json:"rejected"`
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
