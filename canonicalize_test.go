// Copyright (C) 2019 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"testing"
)

type stringCanonTest struct {
	in  string
	out string
}

var stringCanonTests = []stringCanonTest{
	{"", ""},
	{" ", ""},
	{"  ", ""},
	{"abc", "abc"},
	{"aBc", "abc"},
	{"ab c", "ab c"},
	{"ab  c", "ab c"},
	{"ab\n c", "ab c"},
	{" ab c ", "ab c"},
	{" ab  c ", "ab c"},
	{" ab  c", "ab c"},
	{"ab  c ", "ab c"},
	{"abc ", "abc"},
	{"abc  ", "abc"},
	{"  abc  ", "abc"},
	{"  abc ", "abc"},
	{"  abc", "abc"},
	{"  aBc de  f      g\n", "abc de f g"},
}

func TestCanonicalizeRDNString(t *testing.T) {
	for i, test := range stringCanonTests {
		ret := canonicalizeRDNString(test.in)
		if test.out != ret {
			t.Errorf("#%d: canonicalizeRDNString(%q) = %q, want %q", i, test.in, ret, test.out)
		}
	}
}
