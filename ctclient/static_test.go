// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package ctclient

import (
	"testing"
)

func TestFormatTileIndex(t *testing.T) {
	tests := []struct {
		in  uint64
		out string
	}{
		{0, "000"},
		{1, "001"},
		{12, "012"},
		{105, "105"},
		{1000, "x001/000"},
		{1050, "x001/050"},
		{52123, "x052/123"},
		{999001, "x999/001"},
		{1999001, "x001/x999/001"},
		{15999001, "x015/x999/001"},
	}
	for i, test := range tests {
		result := formatTileIndex(test.in)
		if result != test.out {
			t.Errorf("#%d: formatTileIndex(%q) = %q, want %q", i, test.in, result, test.out)
		}
	}
}
