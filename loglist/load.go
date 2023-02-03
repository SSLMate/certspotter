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
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func Load(ctx context.Context, urlOrFile string) (*List, error) {
	if strings.HasPrefix(urlOrFile, "https://") {
		return Fetch(ctx, urlOrFile)
	} else {
		return ReadFile(urlOrFile)
	}
}

func Fetch(ctx context.Context, url string) (*List, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, response.Status)
	}
	return Unmarshal(content)
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
		return nil, fmt.Errorf("Invalid log list: %s", err)
	}
	return list, nil
}
