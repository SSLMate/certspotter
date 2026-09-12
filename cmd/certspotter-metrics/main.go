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
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"software.sslmate.com/src/certspotter/monitor"
)

var programName = os.Args[0]
var Version = "unknown"
var Source = "unknown"

func certspotterVersion() (string, string) {
	if buildinfo, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(buildinfo.Main.Version, "v") {
		return strings.TrimPrefix(buildinfo.Main.Version, "v"), buildinfo.Main.Path
	} else {
		return Version, Source
	}
}

func homedir() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("unable to determine home directory: %w", err))
	}
	return homedir
}
func startedBySupervisor() bool {
	return os.Getenv("SYSTEMD_EXEC_PID") == strconv.Itoa(os.Getpid())
}
func defaultStateDir() string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else if envVar := os.Getenv("STATE_DIRECTORY"); envVar != "" && startedBySupervisor() {
		return envVar
	} else {
		return filepath.Join(homedir(), ".certspotter")
	}
}

// logMetrics is the set of metric values for a single log.
type logMetrics struct {
	logID monitor.LogID

	maxSTHExists         bool
	maxSTHSize           uint64
	maxSTHTimestamp      uint64
	downloadPosition     uint64
	verifiedPosition     uint64
	verifiedSTHExists    bool
	verifiedSTHTimestamp uint64
	unverifiedSTHs       uint64
	malformedEntries     uint64
	healthCheckFailures  uint64
}

// metricFamily describes one of the metrics output by certspotter-metrics.
// All metrics are gauges labeled with the ID of the log they pertain to.
type metricFamily struct {
	name  string
	help  string
	value func(*logMetrics) (uint64, bool)
}

var metricFamilies = []metricFamily{
	{
		name:  "certspotter_log_max_sth_size",
		help:  "Tree size of largest known STH.",
		value: func(m *logMetrics) (uint64, bool) { return m.maxSTHSize, m.maxSTHExists },
	},
	{
		name:  "certspotter_log_max_sth_timestamp",
		help:  "Timestamp (in milliseconds since the Epoch) of largest known STH.",
		value: func(m *logMetrics) (uint64, bool) { return m.maxSTHTimestamp, m.maxSTHExists },
	},
	{
		name:  "certspotter_log_download_position",
		help:  "Number of entries downloaded from the log, including entries not yet verified.",
		value: func(m *logMetrics) (uint64, bool) { return m.downloadPosition, true },
	},
	{
		name:  "certspotter_log_verified_position",
		help:  "Number of entries downloaded from the log and verified against an STH.",
		value: func(m *logMetrics) (uint64, bool) { return m.verifiedPosition, true },
	},
	{
		name:  "certspotter_log_verified_sth_timestamp",
		help:  "Timestamp (in milliseconds since the Epoch) of the largest verified STH (the STH whose size is verified_position).",
		value: func(m *logMetrics) (uint64, bool) { return m.verifiedSTHTimestamp, m.verifiedSTHExists },
	},
	{
		name:  "certspotter_log_unverified_sths",
		help:  "Number of STHs pending verification.",
		value: func(m *logMetrics) (uint64, bool) { return m.unverifiedSTHs, true },
	},
	{
		name:  "certspotter_log_malformed_entries",
		help:  "Number of malformed entries recorded for the log.",
		value: func(m *logMetrics) (uint64, bool) { return m.malformedEntries, true },
	},
	{
		name:  "certspotter_log_health_check_failures",
		help:  "Number of health check failures recorded for the log.",
		value: func(m *logMetrics) (uint64, bool) { return m.healthCheckFailures, true },
	},
}

// gatherMetrics computes the metrics for every log that has a state directory.
// The returned slice is sorted by log ID.
func gatherMetrics(ctx context.Context, state *monitor.FilesystemState) ([]logMetrics, error) {
	logIDs, err := state.ListLogs(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing logs in state directory: %w", err)
	}
	slices.SortFunc(logIDs, monitor.LogID.Compare)

	allMetrics := make([]logMetrics, 0, len(logIDs))
	for _, logID := range logIDs {
		m := logMetrics{logID: logID}

		logState, err := state.LoadLogState(ctx, logID)
		if err != nil {
			return nil, fmt.Errorf("error loading state of log %s: %w", logID.Base64String(), err)
		}
		largestSTH, err := state.LoadLargestSTH(ctx, logID)
		if err != nil {
			return nil, fmt.Errorf("error loading STHs of log %s: %w", logID.Base64String(), err)
		}

		if largestSTH != nil {
			m.maxSTHExists = true
			m.maxSTHSize = largestSTH.TreeSize
			m.maxSTHTimestamp = largestSTH.Timestamp
		} else if logState != nil && logState.VerifiedSTH != nil {
			m.maxSTHExists = true
			m.maxSTHSize = logState.VerifiedSTH.TreeSize
			m.maxSTHTimestamp = logState.VerifiedSTH.Timestamp
		}

		if logState != nil {
			if logState.DownloadPosition != nil {
				m.downloadPosition = logState.DownloadPosition.Size()
			}
			if logState.VerifiedPosition != nil {
				m.verifiedPosition = logState.VerifiedPosition.Size()
			}
			if logState.VerifiedSTH != nil {
				m.verifiedSTHExists = true
				m.verifiedSTHTimestamp = logState.VerifiedSTH.Timestamp
			}
		}

		if unverifiedSTHs, err := state.CountSTHs(ctx, logID); err != nil {
			return nil, fmt.Errorf("error counting STHs of log %s: %w", logID.Base64String(), err)
		} else {
			m.unverifiedSTHs = uint64(unverifiedSTHs)
		}
		if malformedEntries, err := state.CountMalformedEntries(ctx, logID); err != nil {
			return nil, fmt.Errorf("error counting malformed entries of log %s: %w", logID.Base64String(), err)
		} else {
			m.malformedEntries = uint64(malformedEntries)
		}
		if healthCheckFailures, err := state.CountHealthCheckFailures(ctx, logID); err != nil {
			return nil, fmt.Errorf("error counting health check failures of log %s: %w", logID.Base64String(), err)
		} else {
			m.healthCheckFailures = uint64(healthCheckFailures)
		}

		allMetrics = append(allMetrics, m)
	}
	return allMetrics, nil
}

// writeMetrics writes allMetrics to w in the Prometheus text exposition format.
func writeMetrics(w io.Writer, allMetrics []logMetrics) error {
	buf := bufio.NewWriter(w)
	for _, family := range metricFamilies {
		if _, err := fmt.Fprintf(buf, "# HELP %s %s\n", family.name, family.help); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(buf, "# TYPE %s gauge\n", family.name); err != nil {
			return err
		}
		for i := range allMetrics {
			value, include := family.value(&allMetrics[i])
			if !include {
				continue
			}
			if _, err := fmt.Fprintf(buf, "%s{log_id=\"%s\"} %d\n", family.name, allMetrics[i].logID.Base64String(), value); err != nil {
				return err
			}
		}
	}
	return buf.Flush()
}

func main() {
	version, source := certspotterVersion()

	var flags struct {
		stateDir string
		version  bool
	}
	flag.StringVar(&flags.stateDir, "state_dir", defaultStateDir(), "Directory where certspotter stores state. This should be the same directory used by certspotter(8)")
	flag.BoolVar(&flags.version, "version", false, "Print version and exit")
	flag.Parse()

	if flags.version {
		fmt.Fprintf(os.Stdout, "certspotter-metrics version %s (%s)\n", version, source)
		os.Exit(0)
	}

	state := &monitor.FilesystemState{
		StateDir: flags.stateDir,
	}

	allMetrics, err := gatherMetrics(context.Background(), state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
		os.Exit(1)
	}
	if err := writeMetrics(os.Stdout, allMetrics); err != nil {
		fmt.Fprintf(os.Stderr, "%s: error writing metrics: %s\n", programName, err)
		os.Exit(1)
	}
}
