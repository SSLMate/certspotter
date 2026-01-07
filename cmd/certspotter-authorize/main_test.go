// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const testCertPEM = `
-----BEGIN CERTIFICATE-----
MIIGuzCCBSOgAwIBAgIRANubk4g/6c+TF8jITzhFX44wDQYJKoZIhvcNAQELBQAw
YDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDE3MDUGA1UE
AxMuU2VjdGlnbyBQdWJsaWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIENBIERWIFIz
NjAeFw0yNTEyMDIwMDAwMDBaFw0yNjExMjEyMzU5NTlaMBYxFDASBgNVBAMTC3Nz
bG1hdGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA235/3Y/E
4yPAHPa37C7Fgp7KPVjjuTB5vKV9nYIJzfp7NgvDBlf7k5bZFCSsSIj2txhL0hzX
Bwvmy7u7CYR7CApr2Rx2UPOl7Gmlt/DmtfyKac8Iunn2ozuGZDtxq19Go4NL9jl9
e9O3H/lcL/ZFqzbUNlKIOfkOYkOxM3qpQXHTXuhkeI2MJO/S4wX8y8/8uhArWQ9e
h/YrtJlO9fla60kLUlQF7mtJTc+0oB3+N4eF5t2a8Pav00T6lVvH8hMhbY0nZ/tB
CD6/I6yelh8cP094VRJEGWs+zcEuXpz4FsZggkhF/l+AhQ+DfgxZhno4M60kBKC8
Un1BTGX5TjfjJQIDAQABo4IDODCCAzQwHwYDVR0jBBgwFoAUaMASFhgOr872h6Yy
V6NGUV3LBycwHQYDVR0OBBYEFKg2kl8xIzdSxjOEAzlNpdpigAazMA4GA1UdDwEB
/wQEAwIFoDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMEkGA1Ud
IARCMEAwNAYLKwYBBAGyMQECAgcwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0
aWdvLmNvbS9DUFMwCAYGZ4EMAQIBMIGEBggrBgEFBQcBAQR4MHYwTwYIKwYBBQUH
MAKGQ2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1NlcnZlckF1
dGhlbnRpY2F0aW9uQ0FEVlIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3Nw
LnNlY3RpZ28uY29tMIIBfQYKKwYBBAHWeQIEAgSCAW0EggFpAWcAdQDXbX0Q0af1
d8LH6V/XAL/5gskzWmXh0LMBcxfAyMVpdwAAAZrg2UujAAAEAwBGMEQCIApVmNqo
gzJBNbcVXezO5sSvOFE5FaVZVz/eaqnCbG+2AiAT/A7XPtOYHwsE0wmTUBCTV/0l
bF7lk573b3rNtBvP3QB2AK9niDtXsE7dj6bZfvYuqOuBCsdxYPAkXlXWDC/nhYc6
AAABmuDZTFoAAAQDAEcwRQIgODruJKtbjW1QJcQP7ARZAw5FgChfI599pJBA2bbQ
suICIQCskIUnzQCD6taycnQCN3zpu+rsz3Vd4AsMeFDM/cDJ5AB2AKyrMHBs6+yE
MfQT0vSRXxEeQiRDsfKmjE88KzunHgLDAAABmuDZS5kAAAQDAEcwRQIgD9IQCPTc
N88jbz5DUILwmDruTo411Ep5M2ZryNjBkywCIQCFwIyqGZEd+PiFv4l+5LOV3yDW
/zUuimFUoAJH5OIiNDBsBgNVHREEZTBjggtzc2xtYXRlLmNvbYIbKi5odHRwLWFw
cHJvdmFsLnNzbG1hdGUuY29tghFjZXJ0cy5zc2xtYXRlLmNvbYITY29uc29sZS5z
c2xtYXRlLmNvbYIPd3d3LnNzbG1hdGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBgQBR
Pjx14qo9PiYYEE1695CHdctA6up8L+n0MRapZcxALN/cetfGeoR00ZEH+7b1X7Ma
F9GGv1OtJXDoCySlAsdwFKHYtKhrUYRuQXdKGkTjdMzKO/+5kXeZIqgsCR10j8nr
Zq0Zcg2ply4j03/0y7+8ZNC1Erp4DB1Tq7ybgXnyURaNQTHsSkDoxMT/bWIrhGD0
C8kN/ExkFvOBQlzdbuwo2d3v0zSM4mYmnqUhUYHprZllOziYgxIqjM/7mfnDkVAi
ov8yNJtn6EPt1wt6Oo3fC+Ft1T/kbSxeZbqWf3Zgbon5ijmNz+xqkb8br2+JdzM+
8gEIqO6mNoMl0tayzb4a5KDaHxhczMGB3ggBwpVcdLtYBBa41thrgRP0VARqFTFG
IIkC9gPMjScf+uv9CQPsNk3kFI8vN4T3x4/g54N8Mc3M4JxvLaOsBj8dMeyq7v2p
1zE9WRngMUWuPgx0O94c0Pteumg/+pSGVeRapIuYZxXvkmLJ5wmwgYepix+cw1w=
-----END CERTIFICATE-----
`

func TestComputeTBSHash(t *testing.T) {
	certDER, err := parseCertificate([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}
	tbsHash, err := computeTBSHash(certDER)
	if err != nil {
		t.Fatalf("computeTBSHash failed: %v", err)
	}
	if expected := [...]byte{0x3c, 0xf6, 0xb2, 0x44, 0xc2, 0x95, 0x85, 0xdb, 0xfb, 0xfd, 0x42, 0x0a, 0x6a, 0x4c, 0x62, 0xf7, 0x96, 0x8f, 0xa9, 0x05, 0xb4, 0xd6, 0xa4, 0xf5, 0x9d, 0x4d, 0x3b, 0xc9, 0xfa, 0xcb, 0x0c, 0xc8}; expected != tbsHash {
		t.Fatalf("computeTBSHash returned %x; expected %x", tbsHash, expected)
	}
}

func TestCreateNotifiedMarker(t *testing.T) {
	stateDir := t.TempDir()

	certDER, err := parseCertificate([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}

	tbsHash, err := computeTBSHash(certDER)
	if err != nil {
		t.Fatalf("computeTBSHash failed: %v", err)
	}

	// First call should create the marker
	notifiedPath, err := createNotifiedMarker(stateDir, tbsHash)
	if err != nil {
		t.Fatalf("createNotifiedMarker failed: %v", err)
	}

	// Verify marker file exists
	if !fileExists(notifiedPath) {
		t.Fatalf("marker file does not exist: %s", notifiedPath)
	}

	// Verify path structure is correct
	tbsHex := hex.EncodeToString(tbsHash[:])
	expectedPath := filepath.Join(stateDir, "certs", tbsHex[0:2], "."+tbsHex+".notified")
	if notifiedPath != expectedPath {
		t.Fatalf("unexpected marker path: got %s, expected %s", notifiedPath, expectedPath)
	}

	// Second call should succeed (idempotency)
	notifiedPath2, err := createNotifiedMarker(stateDir, tbsHash)
	if err != nil {
		t.Fatalf("createNotifiedMarker second call failed: %v", err)
	}
	if notifiedPath != notifiedPath2 {
		t.Fatalf("second call returned different path: got %s, expected %s", notifiedPath2, notifiedPath)
	}
}

func TestReadCertFile(t *testing.T) {
	// Test reading from a file
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, []byte(testCertPEM), 0644); err != nil {
		t.Fatalf("failed to write test cert: %v", err)
	}

	certBytes, err := readCertFile(certPath)
	if err != nil {
		t.Fatalf("readCertFile failed: %v", err)
	}
	if !bytes.Equal(certBytes, []byte(testCertPEM)) {
		t.Fatal("readCertFile returned different content")
	}
}

func TestFileExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	if fileExists(filepath.Join(tmpDir, "nonexistent")) {
		t.Fatal("fileExists returned true for non-existent file")
	}

	// Test with existing file
	existingFile := filepath.Join(tmpDir, "existing")
	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if !fileExists(existingFile) {
		t.Fatal("fileExists returned false for existing file")
	}
}

func TestEndToEnd(t *testing.T) {
	stateDir := t.TempDir()

	certDER, err := parseCertificate([]byte(testCertPEM))
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}

	tbsHash, err := computeTBSHash(certDER)
	if err != nil {
		t.Fatalf("computeTBSHash failed: %v", err)
	}

	notifiedPath, err := createNotifiedMarker(stateDir, tbsHash)
	if err != nil {
		t.Fatalf("createNotifiedMarker failed: %v", err)
	}

	// Verify the marker file structure matches what monitor/fsstate.go expects
	tbsHex := hex.EncodeToString(tbsHash[:])
	expectedDir := filepath.Join(stateDir, "certs", tbsHex[0:2])
	expectedFile := filepath.Join(expectedDir, "."+tbsHex+".notified")

	if notifiedPath != expectedFile {
		t.Fatalf("unexpected marker path: got %s, expected %s", notifiedPath, expectedFile)
	}

	if !fileExists(expectedFile) {
		t.Fatalf("marker file does not exist: %s", expectedFile)
	}

	// Verify file is empty (as expected by certspotter)
	stat, err := os.Stat(expectedFile)
	if err != nil {
		t.Fatalf("failed to stat marker file: %v", err)
	}
	if stat.Size() != 0 {
		t.Fatalf("marker file should be empty, but has size %d", stat.Size())
	}
}
