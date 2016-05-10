// Copyright (C) 2016 Opsmate, Inc.
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

func doWildcardTest (t *testing.T, dnsName string, wildcard string, expected bool) {
	if MatchesWildcard(dnsName, wildcard) != expected {
		t.Errorf("MatchesWildcard(%q, %q) != %v", dnsName, wildcard, expected)
	}
}

func TestMatchesWildcard(t *testing.T) {
	doWildcardTest(t, "", "", true)
	doWildcardTest(t, "example.com", "example.com", true)
	doWildcardTest(t, "example.org", "example.com", false)
	doWildcardTest(t, "example.com", "", false)
	doWildcardTest(t, "", "example.com", false)
	doWildcardTest(t, "", "*.example.com", false)
	doWildcardTest(t, "", "exam*ple.com", false)
	doWildcardTest(t, "", "exam*ple.co*m", false)
	doWildcardTest(t, "example.org", "example.com", false)
	doWildcardTest(t, "example.org", "*.example.com", false)
	doWildcardTest(t, "example.org", "exam*ple.com", false)
	doWildcardTest(t, "example.org", "exam*ple.co*m", false)
	doWildcardTest(t, "example.com", "*.example.com", false)
	doWildcardTest(t, "www.example.com", "*.example.com", true)
	doWildcardTest(t, "", "*", true)
	doWildcardTest(t, "", "****", true)
	doWildcardTest(t, "a", "****", true)
	doWildcardTest(t, "a", "*", true)
	doWildcardTest(t, "a", "****", true)
	doWildcardTest(t, "abcd", "****", true)
	doWildcardTest(t, "abcdef", "****", true)
	doWildcardTest(t, "www-example.com", "*-example.com", true)
	doWildcardTest(t, "www-example-www.com", "*-example-*.com", true)
	doWildcardTest(t, "examplecom", "example*", true)
	doWildcardTest(t, "example.com", "example*", false)
	doWildcardTest(t, "examplea.com", "example*", false)
}
