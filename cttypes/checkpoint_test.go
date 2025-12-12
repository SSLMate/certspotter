// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package cttypes

import (
	"bytes"
	"software.sslmate.com/src/certspotter/tlstypes"
	"testing"
)

func TestParseCheckpoint(t *testing.T) {
	logID := LogID{0x49, 0x4d, 0x90, 0x49, 0xb8, 0xaf, 0x3e, 0x5a, 0xca, 0xba, 0x99, 0x3e, 0x4c, 0x1f, 0x30, 0x56, 0x73, 0x7a, 0xa9, 0xf9, 0x6d, 0x00, 0xf7, 0xb0, 0xb9, 0xb2, 0x51, 0x06, 0xf7, 0xbe, 0x1a, 0x8f}
	expected := SignedTreeHead{
		TreeSize:  820495916,
		Timestamp: 1719511711300,
		RootHash:  [...]byte{0xc0, 0x3a, 0x6b, 0xe9, 0xf1, 0x1d, 0xc9, 0xcc, 0x20, 0x89, 0xe4, 0x45, 0xa7, 0x3f, 0x61, 0x41, 0xee, 0x82, 0xe8, 0x0d, 0x2d, 0x83, 0xa2, 0xb6, 0x65, 0x53, 0xd4, 0x96, 0xd7, 0x1e, 0xd2, 0x12},
		Signature: tlstypes.DigitallySigned{
			Algorithm: tlstypes.SignatureAndHashAlgorithm{
				Hash:      tlstypes.SHA256,
				Signature: tlstypes.ECDSA,
			},
			Signature: []byte{0x30, 0x46, 0x02, 0x21, 0x00, 0xd0, 0x0d, 0x31, 0x91, 0x50, 0x80, 0x62, 0xfa, 0xb0, 0xf9, 0xf7, 0x63, 0x61, 0x78, 0x95, 0x2b, 0x9c, 0x19, 0x22, 0x3a, 0x1d, 0x08, 0xc5, 0x68, 0x0e, 0xd0, 0x8b, 0x3b, 0x79, 0x18, 0x88, 0x86, 0x02, 0x21, 0x00, 0xd5, 0x74, 0xae, 0x8c, 0x1d, 0x1d, 0x7a, 0x4e, 0x80, 0x6c, 0x36, 0x46, 0x81, 0xb4, 0x7c, 0x91, 0x78, 0xc0, 0x3f, 0xdc, 0xc0, 0xab, 0xa5, 0x90, 0x40, 0x8d, 0x0e, 0xf6, 0x2c, 0x83, 0xa9, 0x34},
		},
	}

	sthStrings := []string{
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\nextension line\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\nextension line\nanother extension line\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n\u2014 someoneelse.example c2lnbmF0dXJlCg==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 someoneelse.example c2lnbmF0dXJlCg==\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\nextension line\nanother extension line\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2c2lnbmF0dXJlCg==\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
	}

	for i, str := range sthStrings {
		parsed, err := ParseCheckpoint([]byte(str), logID)
		if err != nil {
			t.Errorf("%d: Unexpected error: %s", i, err)
			return
		}
		if parsed.TreeSize != expected.TreeSize {
			t.Errorf("%d: wrong tree size", i)
			return
		}
		if parsed.Timestamp != expected.Timestamp {
			t.Errorf("%d: wrong timestamp", i)
			return
		}
		if !bytes.Equal(parsed.RootHash[:], expected.RootHash[:]) {
			t.Errorf("%d: wrong root hash", i)
			return
		}
		if !(parsed.Signature.Algorithm == expected.Signature.Algorithm && bytes.Equal(parsed.Signature.Signature, expected.Signature.Signature)) {
			t.Errorf("%d: wrong signature", i)
			return
		}
	}
}

func TestParseCheckpointFailure(t *testing.T) {
	logID := LogID{0x49, 0x4d, 0x90, 0x49, 0xb8, 0xaf, 0x3e, 0x5a, 0xca, 0xba, 0x99, 0x3e, 0x4c, 0x1f, 0x30, 0x56, 0x73, 0x7a, 0xa9, 0xf9, 0x6d, 0x00, 0xf7, 0xb0, 0xb9, 0xb2, 0x51, 0x06, 0xf7, 0xbe, 0x1a, 0x8f}
	sthStrings := []string{
		"",
		"\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 oak.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 bm90YXNpZ25hdHVyZQo=\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 notbase64!\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916!\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEd!ycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
		"sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n- sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n",
	}

	for i, str := range sthStrings {
		_, err := ParseCheckpoint([]byte(str), logID)
		if err == nil {
			t.Errorf("%d: Unexpected success", i)
			return
		}
	}
}

func TestFormatCheckpoint(t *testing.T) {
	origin := "sycamore.ct.letsencrypt.org/2024h2"
	logID := LogID{0x49, 0x4d, 0x90, 0x49, 0xb8, 0xaf, 0x3e, 0x5a, 0xca, 0xba, 0x99, 0x3e, 0x4c, 0x1f, 0x30, 0x56, 0x73, 0x7a, 0xa9, 0xf9, 0x6d, 0x00, 0xf7, 0xb0, 0xb9, 0xb2, 0x51, 0x06, 0xf7, 0xbe, 0x1a, 0x8f}
	sth := SignedTreeHead{
		TreeSize:  820495916,
		Timestamp: 1719511711300,
		RootHash:  [...]byte{0xc0, 0x3a, 0x6b, 0xe9, 0xf1, 0x1d, 0xc9, 0xcc, 0x20, 0x89, 0xe4, 0x45, 0xa7, 0x3f, 0x61, 0x41, 0xee, 0x82, 0xe8, 0x0d, 0x2d, 0x83, 0xa2, 0xb6, 0x65, 0x53, 0xd4, 0x96, 0xd7, 0x1e, 0xd2, 0x12},
		Signature: tlstypes.DigitallySigned{
			Algorithm: tlstypes.SignatureAndHashAlgorithm{
				Hash:      tlstypes.SHA256,
				Signature: tlstypes.ECDSA,
			},
			Signature: []byte{0x30, 0x46, 0x02, 0x21, 0x00, 0xd0, 0x0d, 0x31, 0x91, 0x50, 0x80, 0x62, 0xfa, 0xb0, 0xf9, 0xf7, 0x63, 0x61, 0x78, 0x95, 0x2b, 0x9c, 0x19, 0x22, 0x3a, 0x1d, 0x08, 0xc5, 0x68, 0x0e, 0xd0, 0x8b, 0x3b, 0x79, 0x18, 0x88, 0x86, 0x02, 0x21, 0x00, 0xd5, 0x74, 0xae, 0x8c, 0x1d, 0x1d, 0x7a, 0x4e, 0x80, 0x6c, 0x36, 0x46, 0x81, 0xb4, 0x7c, 0x91, 0x78, 0xc0, 0x3f, 0xdc, 0xc0, 0xab, 0xa5, 0x90, 0x40, 0x8d, 0x0e, 0xf6, 0x2c, 0x83, 0xa9, 0x34},
		},
	}

	expected := "sycamore.ct.letsencrypt.org/2024h2\n820495916\nwDpr6fEdycwgieRFpz9hQe6C6A0tg6K2ZVPUltce0hI=\n\n\u2014 sycamore.ct.letsencrypt.org/2024h2 PdkIagAAAZBa4n5EBAMASDBGAiEA0A0xkVCAYvqw+fdjYXiVK5wZIjodCMVoDtCLO3kYiIYCIQDVdK6MHR16ToBsNkaBtHyReMA/3MCrpZBAjQ72LIOpNA==\n"

	got := FormatCheckpoint(&sth, origin, logID)
	if string(got) != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}
