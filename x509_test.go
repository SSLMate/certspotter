// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"encoding/asn1"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// printableString builds an asn1.RawValue holding a PrintableString, as
// decodeASN1String expects to see it.
func printableString(s string) asn1.RawValue {
	return asn1.RawValue{Class: 0, Tag: 19, IsCompound: false, Bytes: []byte(s)}
}

func atv(oid asn1.ObjectIdentifier, value string) AttributeTypeAndValue {
	return AttributeTypeAndValue{Type: oid, Value: printableString(value)}
}

// A commonName that is not the first attribute of a multi-valued RDN must still
// be extracted, otherwise a watched name could escape detection.
func TestParseCNsMultiValuedRDN(t *testing.T) {
	rdns := RDNSequence{
		{
			atv(oidOrganization, "Example Org"),
			atv(oidCommonName, "watched.example.com"),
		},
	}
	cns, err := rdns.ParseCNs()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"watched.example.com"}; !slices.Equal(cns, want) {
		t.Errorf("ParseCNs() = %q, want %q", cns, want)
	}
}

func TestParseCNsMultipleCNs(t *testing.T) {
	rdns := RDNSequence{
		{atv(oidCommonName, "a.example.com")},
		{
			atv(oidOrganizationalUnit, "Dept"),
			atv(oidCommonName, "b.example.com"),
		},
	}
	cns, err := rdns.ParseCNs()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example.com", "b.example.com"}; !slices.Equal(cns, want) {
		t.Errorf("ParseCNs() = %q, want %q", cns, want)
	}
}

func TestRDNSequenceStringEscaping(t *testing.T) {
	tests := []struct {
		name string
		rdns RDNSequence
		want string
	}{
		{
			name: "nul byte",
			rdns: RDNSequence{{atv(oidCommonName, "ev\x00il")}},
			want: `CN=ev\x00il`,
		},
		{
			name: "backslash and comma",
			rdns: RDNSequence{{atv(oidOrganization, `a\b,c`)}},
			want: `O=a\\b\,c`,
		},
		{
			name: "control characters",
			rdns: RDNSequence{{atv(oidCommonName, "a\tb\nc")}},
			want: `CN=a\x09b\x0ac`,
		},
		{
			name: "multi-valued rdn joined with plus",
			rdns: RDNSequence{{
				atv(oidOrganization, "Org"),
				atv(oidCommonName, "host.example.com"),
			}},
			want: "O=Org+CN=host.example.com",
		},
		{
			name: "separate rdns joined with comma",
			rdns: RDNSequence{
				{atv(oidCommonName, "host.example.com")},
				{atv(oidOrganization, "Org")},
			},
			want: "CN=host.example.com, O=Org",
		},
		{
			name: "printable unicode passes through",
			rdns: RDNSequence{{AttributeTypeAndValue{
				Type:  oidOrganization,
				Value: asn1.RawValue{Class: 0, Tag: 12, Bytes: []byte("café")}, // UTF8String
			}}},
			want: "O=café",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rdns.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Regression test for the denial of service in which a NUL byte in a certificate
// Subject/Issuer DN, placed into a hook script's environment, was rejected by
// os/exec and aborted notification (crashing the whole monitor). The escaped DN
// must be usable as an environment variable value.
func TestRDNSequenceStringIsExecSafe(t *testing.T) {
	rdns := RDNSequence{{atv(oidCommonName, "ev\x00il\x01\x02")}}
	dn := rdns.String()
	if strings.ContainsRune(dn, 0) {
		t.Fatalf("DN string still contains a NUL byte: %q", dn)
	}
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	cmd.Env = []string{"SUBJECT_DN=" + dn}
	if err := cmd.Run(); err != nil {
		t.Fatalf("exec with SUBJECT_DN=%q failed: %v", dn, err)
	}
}
