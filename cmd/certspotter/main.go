// Copyright (C) 2016, 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	insecurerand "math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/certspotter/monitor"
)

var programName = os.Args[0]

const defaultLogList = "https://loglist.certspotter.org/monitor.json"

func certspotterVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if strings.HasPrefix(info.Main.Version, "v") {
		return info.Main.Version
	}
	var vcs, vcsRevision, vcsModified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs":
			vcs = s.Value
		case "vcs.revision":
			vcsRevision = s.Value
		case "vcs.modified":
			vcsModified = s.Value
		}
	}
	if vcs == "git" && vcsRevision != "" && vcsModified == "true" {
		return vcsRevision + "+"
	} else if vcs == "git" && vcsRevision != "" {
		return vcsRevision
	}
	return "unknown"
}

func homedir() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("unable to determine home directory: %w", err))
	}
	return homedir
}
func defaultStateDir() string {
	if envVar := os.Getenv("CERTSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return filepath.Join(homedir(), ".certspotter")
	}
}
func defaultConfigDir() string {
	if envVar := os.Getenv("CERTSPOTTER_CONFIG_DIR"); envVar != "" {
		return envVar
	} else {
		return filepath.Join(homedir(), ".certspotter")
	}
}

func readWatchListFile(filename string) (monitor.WatchList, error) {
	file, err := os.Open(filename)
	if err != nil {
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		return nil, err
	}
	defer file.Close()
	return monitor.ReadWatchList(file)
}

func appendFunc(slice *[]string) func(string) error {
	return func(value string) error {
		*slice = append(*slice, value)
		return nil
	}
}

func main() {
	insecurerand.Seed(time.Now().UnixNano()) // TODO: remove after upgrading to Go 1.20

	loglist.UserAgent = fmt.Sprintf("certspotter/%s (%s; %s; %s)", certspotterVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)

	var flags struct {
		batchSize   int // TODO-4: respect this option
		email       []string
		healthcheck time.Duration
		logs        string
		noSave      bool
		script      string
		startAtEnd  bool
		stateDir    string
		stdout      bool
		verbose     bool
		version     bool
		watchlist   string
	}
	flag.IntVar(&flags.batchSize, "batch_size", 1000, "Max number of entries to request per call to get-entries (advanced)")
	flag.Func("email", "Email address to contact when matching certificate is discovered (repeatable)", appendFunc(&flags.email))
	flag.DurationVar(&flags.healthcheck, "healthcheck", 24*time.Hour, "How frequently to perform a healt check")
	flag.StringVar(&flags.logs, "logs", defaultLogList, "File path or URL of JSON list of logs to monitor")
	flag.BoolVar(&flags.noSave, "no_save", false, "Do not save a copy of matching certificates in state directory")
	flag.StringVar(&flags.script, "script", "", "Program to execute when a matching certificate is discovered")
	flag.BoolVar(&flags.startAtEnd, "start_at_end", false, "Start monitoring logs from the end rather than the beginning (saves considerable bandwidth)")
	flag.StringVar(&flags.stateDir, "state_dir", defaultStateDir(), "Directory for storing log position and discovered certificates")
	flag.BoolVar(&flags.stdout, "stdout", false, "Write matching certificates to stdout")
	flag.BoolVar(&flags.verbose, "verbose", false, "Be verbose")
	flag.BoolVar(&flags.version, "version", false, "Print version and exit")
	flag.StringVar(&flags.watchlist, "watchlist", filepath.Join(defaultConfigDir(), "watchlist"), "File containing domain names to watch")
	flag.Parse()

	if flags.version {
		fmt.Fprintf(os.Stdout, "certspotter version %s\n", certspotterVersion())
		os.Exit(0)
	}

	if len(flags.email) == 0 && len(flags.script) == 0 && flags.stdout == false {
		fmt.Fprintf(os.Stderr, "%s: at least one of -email, -script, or -stdout must be specified (see -help for details)\n", programName)
		os.Exit(2)
	}

	config := &monitor.Config{
		LogListSource:       flags.logs,
		StateDir:            flags.stateDir,
		SaveCerts:           !flags.noSave,
		StartAtEnd:          flags.startAtEnd,
		Verbose:             flags.verbose,
		Script:              flags.script,
		Email:               flags.email,
		Stdout:              flags.stdout,
		HealthCheckInterval: flags.healthcheck,
	}

	if flags.watchlist == "-" {
		watchlist, err := monitor.ReadWatchList(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: error reading watchlist from standard in: %s\n", programName, err)
			os.Exit(1)
		}
		config.WatchList = watchlist
	} else {
		watchlist, err := readWatchListFile(flags.watchlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: error reading watchlist from %q: %s\n", programName, flags.watchlist, err)
			os.Exit(1)
		}
		config.WatchList = watchlist
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := monitor.Run(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
		os.Exit(1)
	}
}
