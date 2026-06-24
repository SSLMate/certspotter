// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package ctclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mkResponse(body string) *http.Response {
	return &http.Response{Body: io.NopCloser(strings.NewReader(body))}
}

func TestReadResponseBody(t *testing.T) {
	// under the limit
	if body, err := readResponseBody(mkResponse("hello"), 10); err != nil {
		t.Errorf("unexpected error under limit: %v", err)
	} else if string(body) != "hello" {
		t.Errorf("got %q, want %q", body, "hello")
	}

	// exactly at the limit
	if body, err := readResponseBody(mkResponse("0123456789"), 10); err != nil {
		t.Errorf("unexpected error at exact limit: %v", err)
	} else if len(body) != 10 {
		t.Errorf("got %d bytes, want 10", len(body))
	}

	// one byte over the limit
	if _, err := readResponseBody(mkResponse("0123456789X"), 10); err == nil {
		t.Errorf("expected error for oversize body, got nil")
	}
}

// Confirm the cap is actually wired into get(): a body larger than the limit is
// rejected with an error instead of being buffered in full.
func TestGetEnforcesResponseLimit(t *testing.T) {
	const bodyLen = maxResponseBytes + 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32*1024)
		for written := 0; written < bodyLen; written += len(buf) {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	if _, err := get(context.Background(), server.Client(), server.URL); err == nil {
		t.Errorf("get() accepted an over-limit response body; expected an error")
	} else if !strings.Contains(err.Error(), "maximum allowed size") {
		t.Errorf("unexpected error: %v", err)
	}
}

// A normal-sized response still round-trips correctly.
func TestGetReadsNormalBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "tile-data")
	}))
	defer server.Close()

	body, err := get(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "tile-data" {
		t.Errorf("got %q, want %q", body, "tile-data")
	}
}
