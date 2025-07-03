// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package mozilla_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"software.sslmate.com/src/certspotter/loglist/mozilla"
)

func ExampleParse() {
	resp, err := http.Get("https://hg-edge.mozilla.org/mozilla-central/raw-file/tip/security/ct/CTKnownLogs.h")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatal(resp.Status)
	}
	logs, operators, err := mozilla.Parse(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
	fmt.Fprintln(tw, "Operator\tName")
	for _, o := range operators {
		fmt.Fprintf(tw, "%d\t%s\n", o.ID, o.Name)
	}
	tw.Flush()

	tw = tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
	fmt.Fprintln(tw, "LogID\tState\tTimestamp\tOperator\tName")
	for _, l := range logs {
		hash := sha256.Sum256(l.Key)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n",
			base64.StdEncoding.EncodeToString(hash[:]),
			l.State, l.Timestamp.UTC().Format(time.RFC3339), l.OperatorIndex, l.Name)
	}
	tw.Flush()
}
