// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

// Package ctclient implements a client for monitoring RFC6962 and static-ct-api Certificate Transparency logs
package ctclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Create an HTTP client suitable for communicating with CT logs.  dialContext, if non-nil, is used for dialing.
func NewHTTPClient(dialContext func(context.Context, string, string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				// We have to disable TLS certificate validation because because several logs
				// (WoSign, StartCom, GDCA) use certificates that are not widely trusted.
				// Since we verify that every response we receive from the log is signed
				// by the log's CT public key (either directly, or indirectly via the Merkle Tree),
				// TLS certificate validation is not actually necessary.  (We don't want to manage
				// our own trust store because that adds undesired complexity and would require
				// updating should a log ever change to a different CA.)
				InsecureSkipVerify: true,
			},
			DialContext: dialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects not followed")
		},
		Timeout: 60 * time.Second,
	}
}

var defaultHTTPClient = NewHTTPClient(nil)

func get(ctx context.Context, httpClient *http.Client, fullURL string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "") // Don't send a User-Agent to make life harder for malicious logs

	if httpClient == nil {
		httpClient = defaultHTTPClient
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Get %q: error reading response: %w", fullURL, err)
	}

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("Get %q: %s (%q)", fullURL, response.Status, string(responseBody))
	}

	return responseBody, nil
}

func getJSON(ctx context.Context, httpClient *http.Client, fullURL string, response any) error {
	responseBytes, err := get(ctx, httpClient, fullURL)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(responseBytes, response); err != nil {
		return fmt.Errorf("Get %q: error parsing response JSON: %w", fullURL, err)
	}
	return nil
}

func getRoots(ctx context.Context, httpClient *http.Client, logURL *url.URL) ([][]byte, error) {
	fullURL := logURL.JoinPath("/ct/v1/get-roots").String()
	var parsedResponse struct {
		Certificates [][]byte `json:"certificates"`
	}
	if err := getJSON(ctx, httpClient, fullURL, &parsedResponse); err != nil {
		return nil, err
	}
	return parsedResponse.Certificates, nil
}
