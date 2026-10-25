// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package loglist

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testLogDescription = "Test Log"

func testListJSON(t *testing.T) []byte {
	t.Helper()
	key := []byte("not a real log key")
	list := &List{
		Version: "test",
		Operators: []Operator{{
			Name: "Test Operator",
			Logs: []Log{{
				Key:         key,
				LogID:       sha256.Sum256(key),
				MMD:         86400,
				URL:         "https://ct.example.com/",
				Description: testLogDescription,
			}},
		}},
	}
	jsonBytes, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return jsonBytes
}

func generateRSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return privkey
}

func generateECDSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privkey
}

// marshalPubkey returns the PKIX DER encoding of privkey's public key.
func marshalPubkey(t *testing.T, privkey crypto.Signer) []byte {
	t.Helper()
	pubkey, err := x509.MarshalPKIXPublicKey(privkey.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pubkey
}

// signTestData signs data with privkey using SHA-256.  For RSA keys this
// produces a PKCS #1 v1.5 signature, and for ECDSA keys an ASN.1 signature.
func signTestData(t *testing.T, privkey crypto.Signer, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	signature, err := privkey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

type zipEntry struct {
	name    string
	content []byte
}

func makeZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, entry := range entries {
		f, err := w.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// makeSignedZip returns a ZIP archive in Google's format, named baseName + ".zip",
// containing the test log list signed by privkey.
func makeSignedZip(t *testing.T, privkey crypto.Signer, baseName string) []byte {
	t.Helper()
	jsonBytes := testListJSON(t)
	return makeZip(t,
		zipEntry{baseName + ".json", jsonBytes},
		zipEntry{baseName + ".sig", signTestData(t, privkey, jsonBytes)},
	)
}

func checkTestList(t *testing.T, list *List) {
	t.Helper()
	if len(list.Operators) != 1 || len(list.Operators[0].Logs) != 1 {
		t.Fatalf("unexpected list contents: %+v", list)
	}
	if desc := list.Operators[0].Logs[0].Description; desc != testLogDescription {
		t.Fatalf("log description = %q, want %q", desc, testLogDescription)
	}
}

func checkInvalidSignature(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "invalid log list signature") {
		t.Fatalf("got error %v, want invalid signature error", err)
	}
}

func TestUnmarshalJSON(t *testing.T) {
	list, err := Unmarshal(testListJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	checkTestList(t, list)
}

func TestUnmarshalSigned(t *testing.T) {
	keyTypes := []struct {
		name     string
		generate func(*testing.T) crypto.Signer
	}{
		{"RSA", generateRSAKey},
		{"ECDSA", generateECDSAKey},
	}
	for _, keyType := range keyTypes {
		t.Run(keyType.name, func(t *testing.T) {
			privkey := keyType.generate(t)
			pubkey := marshalPubkey(t, privkey)
			zipBytes := makeSignedZip(t, privkey, "log_list")

			list, err := UnmarshalSigned(zipBytes, "log_list.zip", pubkey)
			if err != nil {
				t.Fatal(err)
			}
			checkTestList(t, list)

			t.Run("WrongKey", func(t *testing.T) {
				for _, otherKeyType := range keyTypes {
					otherPubkey := marshalPubkey(t, otherKeyType.generate(t))
					_, err := UnmarshalSigned(zipBytes, "log_list.zip", otherPubkey)
					checkInvalidSignature(t, err)
				}
			})

			t.Run("TamperedJSON", func(t *testing.T) {
				jsonBytes := testListJSON(t)
				signature := signTestData(t, privkey, jsonBytes)
				tampered := bytes.Replace(jsonBytes, []byte(testLogDescription), []byte("Evil Log"), 1)
				if bytes.Equal(tampered, jsonBytes) {
					t.Fatal("failed to tamper with JSON")
				}
				zipBytes := makeZip(t, zipEntry{"log_list.json", tampered}, zipEntry{"log_list.sig", signature})
				_, err := UnmarshalSigned(zipBytes, "log_list.zip", pubkey)
				checkInvalidSignature(t, err)
			})

			t.Run("MissingSignature", func(t *testing.T) {
				zipBytes := makeZip(t, zipEntry{"log_list.json", testListJSON(t)})
				_, err := UnmarshalSigned(zipBytes, "log_list.zip", pubkey)
				if err == nil || !strings.Contains(err.Error(), "log_list.sig") {
					t.Fatalf("got error %v, want error about missing log_list.sig", err)
				}
			})

			t.Run("WrongArchiveName", func(t *testing.T) {
				_, err := UnmarshalSigned(zipBytes, "all_logs_list.zip", pubkey)
				if err == nil || !strings.Contains(err.Error(), "all_logs_list.json") {
					t.Fatalf("got error %v, want error about missing all_logs_list.json", err)
				}
			})

			t.Run("NotAZip", func(t *testing.T) {
				_, err := UnmarshalSigned(testListJSON(t), "log_list.zip", pubkey)
				if err == nil {
					t.Fatal("expected error when content is not a zip archive")
				}
			})

			t.Run("OversizedJSON", func(t *testing.T) {
				huge := make([]byte, maxResponseBytes+1)
				zipBytes := makeZip(t, zipEntry{"log_list.json", huge}, zipEntry{"log_list.sig", signTestData(t, privkey, huge)})
				_, err := UnmarshalSigned(zipBytes, "log_list.zip", pubkey)
				if err == nil || !strings.Contains(err.Error(), "exceeds maximum allowed size") {
					t.Fatalf("got error %v, want error about maximum size", err)
				}
			})
		})
	}

	t.Run("InvalidPubkey", func(t *testing.T) {
		privkey := generateECDSAKey(t)
		_, err := UnmarshalSigned(makeSignedZip(t, privkey, "log_list"), "log_list.zip", []byte{1, 2, 3})
		if err == nil {
			t.Fatal("expected error for invalid public key")
		}
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		pubkey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubkeyDER, err := x509.MarshalPKIXPublicKey(pubkey)
		if err != nil {
			t.Fatal(err)
		}
		zipBytes := makeZip(t, zipEntry{"log_list.json", testListJSON(t)}, zipEntry{"log_list.sig", []byte("not a real signature")})
		_, err = UnmarshalSigned(zipBytes, "log_list.zip", pubkeyDER)
		if err == nil || !strings.Contains(err.Error(), "unsupported key type") {
			t.Fatalf("got error %v, want error about unsupported key type", err)
		}
	})
}

func TestReadFileSignedZip(t *testing.T) {
	privkey := generateECDSAKey(t)
	pubkey := marshalPubkey(t, privkey)
	dir := t.TempDir()

	zipPath := filepath.Join(dir, "all_logs_list.zip")
	if err := os.WriteFile(zipPath, makeSignedZip(t, privkey, "all_logs_list"), 0666); err != nil {
		t.Fatal(err)
	}
	list, err := ReadFile(zipPath, pubkey)
	if err != nil {
		t.Fatal(err)
	}
	checkTestList(t, list)

	// The archive's contents must match the archive's file name.
	misnamedPath := filepath.Join(dir, "log_list.zip")
	if err := os.WriteFile(misnamedPath, makeSignedZip(t, privkey, "all_logs_list"), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(misnamedPath, pubkey); err == nil {
		t.Fatal("expected error when archive name does not match its contents")
	}
}

func TestFetchSignedZip(t *testing.T) {
	privkey := generateRSAKey(t)
	pubkey := marshalPubkey(t, privkey)
	zipBytes := makeSignedZip(t, privkey, "log_list")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/log_list/v3/log_list.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(zipBytes)
	}))
	defer server.Close()

	ctx := context.Background()
	for _, url := range []string{
		server.URL + "/ct/log_list/v3/log_list.zip",
		server.URL + "/ct/log_list/v3/log_list.zip?cachebust=1",
	} {
		list, err := Fetch(ctx, url, pubkey)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		checkTestList(t, list)
	}

	otherPubkey := marshalPubkey(t, generateECDSAKey(t))
	_, err := Fetch(ctx, server.URL+"/ct/log_list/v3/log_list.zip", otherPubkey)
	checkInvalidSignature(t, err)
}

// fetchChromePubkey downloads Chrome's log list public key and returns it in PKIX DER form.
func fetchChromePubkey(t *testing.T) []byte {
	t.Helper()
	resp, err := http.Get("https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}
	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("public key is not PEM-encoded")
	}
	return block.Bytes
}

func TestChromePubkey(t *testing.T) {
	key, err := x509.ParsePKIXPublicKey(ChromePubkey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Fatalf("ChromePubkey is %T, want *rsa.PublicKey", key)
	}
}

// TestChromeLogList verifies a snapshot of Chrome's log list, taken from
// https://www.gstatic.com/ct/log_list/v3/log_list.zip on 2026-10-25.
func TestChromeLogList(t *testing.T) {
	const path = "testdata/log_list.zip"

	list, err := ReadFile(path, ChromePubkey)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Operators) == 0 {
		t.Fatal("no operators in log list")
	}

	wrongPubkey := marshalPubkey(t, generateECDSAKey(t))
	_, err = ReadFile(path, wrongPubkey)
	checkInvalidSignature(t, err)
}

func TestFetchChrome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	const url = "https://www.gstatic.com/ct/log_list/v3/log_list.zip"
	ctx := context.Background()

	if livePubkey := fetchChromePubkey(t); !bytes.Equal(livePubkey, ChromePubkey) {
		t.Fatal("ChromePubkey does not match the public key currently published by Chrome")
	}

	list, err := Fetch(ctx, url, ChromePubkey)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Operators) == 0 {
		t.Fatal("no operators in log list")
	}

	wrongPubkey := marshalPubkey(t, generateECDSAKey(t))
	_, err = Fetch(ctx, url, wrongPubkey)
	checkInvalidSignature(t, err)
}
