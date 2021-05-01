// Copyright (C) 2020 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package loglist

import (
	"encoding/json"
	"fmt"
	"net/http"
	"io/ioutil"
	"strings"
)

func Load(urlOrFile string) (*List, error) {
	if strings.HasPrefix(urlOrFile, "https://") {
		return Fetch(urlOrFile)
	} else {
		return ReadFile(urlOrFile)
	}
}

func Fetch(url string) (*List, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	content, err := ioutil.ReadAll(response.Body)
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
	content, err := ioutil.ReadFile(filename)
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
