// Copyright (C) 2020, 2023 Opsmate, Inc.
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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var UserAgent = ""

// maxResponseBytes bounds the size of a log list we are willing to read into memory.
// It applies both to the data downloaded from a URL and to each file read from a ZIP archive.
const maxResponseBytes = 16 << 20 // 16 MiB

// httpClient is used for fetching log lists.
var httpClient = &http.Client{
	Timeout: 60 * time.Second,
}

type ModificationToken struct {
	etag     string
	modified time.Time
}

var ErrNotModified = errors.New("loglist has not been modified")

func newModificationToken(response *http.Response) *ModificationToken {
	token := &ModificationToken{
		etag: response.Header.Get("ETag"),
	}
	if t, err := time.Parse(http.TimeFormat, response.Header.Get("Last-Modified")); err == nil {
		token.modified = t
	}
	return token
}

func (token *ModificationToken) setRequestHeaders(request *http.Request) {
	if token.etag != "" {
		request.Header.Set("If-None-Match", token.etag)
	} else if !token.modified.IsZero() {
		request.Header.Set("If-Modified-Since", token.modified.Format(http.TimeFormat))
	}
}

// Load loads a log list from a https:// URL or a file.
//
// If pubkey is nil, the URL or file must contain a JSON log list.
//
// If pubkey is non-nil, it must be a DER-encoded PKIX public key for
// an RSA or ECDSA key, and the URL or file must be a ZIP archive in the
// format published by Google, containing a JSON log list and its signature.
// The filenames must match the last component of the URL or file path: for
// example, log_list.zip must contain log_list.json and log_list.sig.
// The signature must be an RSA PKCS #1 v1.5 signature or an ASN.1
// DER-encoded ECDSA signature over the SHA-256 hash of the JSON file.
// The JSON log list must contain a log_list_timestamp that is no more
// than 48 hours in the past, and if it contains a log_list_name, it must
// equal the base name of the archive (e.g. "log_list" for log_list.zip).
func Load(ctx context.Context, urlOrFile string, pubkey []byte) (*List, error) {
	list, _, err := LoadIfModified(ctx, urlOrFile, pubkey, nil)
	return list, err
}

// LoadIfModified is like [Load], but if token is non-nil, it returns
// [ErrNotModified] if the log list has not changed since the token was
// returned by a previous call to LoadIfModified.
func LoadIfModified(ctx context.Context, urlOrFile string, pubkey []byte, token *ModificationToken) (*List, *ModificationToken, error) {
	if strings.HasPrefix(urlOrFile, "https://") {
		return FetchIfModified(ctx, urlOrFile, pubkey, token)
	} else {
		list, err := ReadFile(urlOrFile, pubkey)
		return list, nil, err
	}
}

// Fetch loads a log list from an https:// URL.  See [Load] for the meaning of pubkey.
func Fetch(ctx context.Context, url string, pubkey []byte) (*List, error) {
	list, _, err := FetchIfModified(ctx, url, pubkey, nil)
	return list, err
}

// FetchIfModified is like [Fetch], but if token is non-nil, it returns
// [ErrNotModified] if the log list has not changed since the token was
// returned by a previous call to FetchIfModified.
func FetchIfModified(ctx context.Context, url string, pubkey []byte, token *ModificationToken) (*List, *ModificationToken, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("User-Agent", UserAgent)
	if token != nil {
		token.setRequestHeaders(request)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	response.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	if len(content) > maxResponseBytes {
		return nil, nil, fmt.Errorf("%s: response body exceeds maximum allowed size of %d bytes", url, maxResponseBytes)
	}
	if token != nil && response.StatusCode == http.StatusNotModified {
		return nil, nil, ErrNotModified
	}
	if response.StatusCode != 200 {
		return nil, nil, fmt.Errorf("%s: %s", url, response.Status)
	}
	list, err := unmarshal(content, path.Base(request.URL.Path), pubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing %s: %w", url, err)
	}
	return list, newModificationToken(response), err
}

// ReadFile loads a log list from a file.  See [Load] for the meaning of pubkey.
func ReadFile(filename string, pubkey []byte) (*List, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return unmarshal(content, filepath.Base(filename), pubkey)
}

func unmarshal(content []byte, filename string, pubkey []byte) (*List, error) {
	if pubkey == nil {
		return Unmarshal(content)
	} else {
		return UnmarshalSigned(content, filename, pubkey)
	}
}

// Unmarshal parses a JSON log list.
func Unmarshal(jsonBytes []byte) (*List, error) {
	list := new(List)
	if err := json.Unmarshal(jsonBytes, list); err != nil {
		return nil, err
	}
	if err := list.Validate(); err != nil {
		return nil, fmt.Errorf("invalid log list: %s", err)
	}
	return list, nil
}

// UnmarshalSigned parses a log list from a ZIP archive after verifying its
// signature with pubkey, which must be a DER-encoded PKIX public key for
// an RSA or ECDSA key. filename is the name of the archive, which is used to
// determine the names of the JSON and signature files within the archive,
// and the expected log_list_name.  The log list must contain a
// log_list_timestamp that is no more than 48 hours in the past.
// See [Load] for details.
func UnmarshalSigned(zipBytes []byte, filename string, pubkey []byte) (*List, error) {
	return unmarshalSigned(zipBytes, filename, pubkey, time.Now())
}

// unmarshalSigned implements [UnmarshalSigned], using now as the current
// time when checking the age of the log list.
func unmarshalSigned(zipBytes []byte, filename string, pubkey []byte, now time.Time) (*List, error) {
	key, err := x509.ParsePKIXPublicKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid log list public key: %w", err)
	}

	archive, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("invalid zip archive: %w", err)
	}

	baseName := strings.TrimSuffix(filename, path.Ext(filename))
	jsonBytes, err := readZipFile(archive, baseName+".json")
	if err != nil {
		return nil, err
	}
	signature, err := readZipFile(archive, baseName+".sig")
	if err != nil {
		return nil, err
	}

	if err := verifySignature(key, jsonBytes, signature); err != nil {
		return nil, fmt.Errorf("invalid log list signature: %w", err)
	}

	list, err := Unmarshal(jsonBytes)
	if err != nil {
		return nil, err
	}
	if err := list.validateSigned(baseName, now); err != nil {
		return nil, fmt.Errorf("invalid log list: %w", err)
	}
	return list, nil
}

func verifySignature(key crypto.PublicKey, data, signature []byte) error {
	digest := sha256.Sum256(data)
	switch key := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return errors.New("ECDSA verification error")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %T (only *rsa.PublicKey and *ecdsa.PublicKey supported)", key)
	}
}

func readZipFile(archive *zip.Reader, name string) ([]byte, error) {
	var file *zip.File
	for _, f := range archive.File {
		if f.Name == name {
			file = f
			break
		}
	}
	if file == nil {
		return nil, fmt.Errorf("zip archive does not contain %s", name)
	}
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("error opening %s in zip archive: %w", name, err)
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("error reading %s from zip archive: %w", name, err)
	}
	if len(content) > maxResponseBytes {
		return nil, fmt.Errorf("%s in zip archive exceeds maximum allowed size of %d bytes", name, maxResponseBytes)
	}
	return content, nil
}
