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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var UserAgent = "software.sslmate.com/src/certspotter"

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

func Load(ctx context.Context, urlOrFile string) (*List, error) {
	list, _, err := LoadIfModified(ctx, urlOrFile, nil)
	return list, err
}

func LoadIfModified(ctx context.Context, urlOrFile string, token *ModificationToken) (*List, *ModificationToken, error) {
	if strings.HasPrefix(urlOrFile, "https://") {
		return FetchIfModified(ctx, urlOrFile, token)
	} else {
		list, err := ReadFile(urlOrFile)
		return list, nil, err
	}
}

func Fetch(ctx context.Context, url string) (*List, error) {
	list, _, err := FetchIfModified(ctx, url, nil)
	return list, err
}

func FetchIfModified(ctx context.Context, url string, token *ModificationToken) (*List, *ModificationToken, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("User-Agent", UserAgent)
	if token != nil {
		token.setRequestHeaders(request)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	content, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	if token != nil && response.StatusCode == http.StatusNotModified {
		return nil, nil, ErrNotModified
	}
	if response.StatusCode != 200 {
		return nil, nil, fmt.Errorf("%s: %s", url, response.Status)
	}
	list, err := Unmarshal(content)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing %s: %w", url, err)
	}
	return list, newModificationToken(response), err
}

func ReadFile(filename string) (*List, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return Unmarshal(content)
}

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
