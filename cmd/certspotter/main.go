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
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"software.sslmate.com/src/certspotter/ctclient"
	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/certspotter/monitor"
)

var programName = os.Args[0]
var Version = ""

const defaultLogList = "https://loglist.certspotter.org/monitor.json"

func certspotterVersion() string {
	if Version != "" {
		return Version + "?"
	} else if info, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(info.Main.Version, "v") {
		return info.Main.Version
	} else {
		return "unknown"
	}
}

func fileExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
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
func defaultCacheDir() string {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(fmt.Errorf("unable to determine user cache directory: %w", err))
	}
	return filepath.Join(userCacheDir, "certspotter")
}
func defaultWatchListPath() string {
	return filepath.Join(defaultConfigDir(), "watchlist")
}
func defaultWatchListPathIfExists() string {
	if fileExists(defaultWatchListPath()) {
		return defaultWatchListPath()
	} else {
		return ""
	}
}
func defaultScriptDir() string {
	return filepath.Join(defaultConfigDir(), "hooks.d")
}
func defaultEmailFile() string {
	return filepath.Join(defaultConfigDir(), "email_recipients")
}

func simplifyError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}

	return err
}

func readWatchListFile(filename string) (monitor.WatchList, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, simplifyError(err)
	}
	defer file.Close()
	return monitor.ReadWatchList(file)
}

func readEmailFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, simplifyError(err)
	}
	defer file.Close()

	var emails []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		emails = append(emails, line)
	}
	return emails, err
}

func appendFunc(slice *[]string) func(string) error {
	return func(value string) error {
		*slice = append(*slice, value)
		return nil
	}
}

func main() {
	loglist.UserAgent = fmt.Sprintf("certspotter/%s (%s; %s; %s)", certspotterVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	ctclient.UserAgent = fmt.Sprintf("certspotter/%s (+https://github.com/SSLMate/certspotter)", certspotterVersion())

	var flags struct {
		batchSize   bool
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
	flag.Func("batch_size", "Obsolete; do not use", func(string) error { flags.batchSize = true; return nil }) // TODO: remove in 0.21.0
	flag.Func("email", "Email address to contact when matching certificate is discovered (repeatable)", appendFunc(&flags.email))
	flag.DurationVar(&flags.healthcheck, "healthcheck", 24*time.Hour, "How frequently to perform a health check")
	flag.StringVar(&flags.logs, "logs", defaultLogList, "File path or URL of JSON list of logs to monitor")
	flag.BoolVar(&flags.noSave, "no_save", false, "Do not save a copy of matching certificates in state directory")
	flag.StringVar(&flags.script, "script", "", "Program to execute when a matching certificate is discovered")
	flag.BoolVar(&flags.startAtEnd, "start_at_end", false, "Start monitoring new logs from the end rather than the beginning (saves considerable bandwidth)")
	flag.StringVar(&flags.stateDir, "state_dir", defaultStateDir(), "Directory for storing log position and discovered certificates")
	flag.BoolVar(&flags.stdout, "stdout", false, "Write matching certificates to stdout")
	flag.BoolVar(&flags.verbose, "verbose", false, "Print detailed information about certspotter's operation to stderr")
	flag.BoolVar(&flags.version, "version", false, "Print version and exit")
	flag.StringVar(&flags.watchlist, "watchlist", defaultWatchListPathIfExists(), "File containing domain names to watch")
	flag.Parse()

	if flags.batchSize {
		fmt.Fprintf(os.Stderr, "%s: -batch_size is obsolete; please remove it from your command line\n", programName)
		os.Exit(2)
	}
	if flags.version {
		fmt.Fprintf(os.Stdout, "certspotter version %s\n", certspotterVersion())
		os.Exit(0)
	}
	if flags.watchlist == "" {
		fmt.Fprintf(os.Stderr, "%s: watch list not found: please create %s or specify alternative path using -watchlist\n", programName, defaultWatchListPath())
		os.Exit(2)
	}

	fsstate := &monitor.FilesystemState{
		StateDir:  flags.stateDir,
		CacheDir:  defaultCacheDir(),
		SaveCerts: !flags.noSave,
		Script:    flags.script,
		ScriptDir: defaultScriptDir(),
		Email:     flags.email,
		Stdout:    flags.stdout,
		Quiet:     !flags.verbose,
	}
	config := &monitor.Config{
		LogListSource:       flags.logs,
		State:               fsstate,
		StartAtEnd:          flags.startAtEnd,
		Verbose:             flags.verbose,
		HealthCheckInterval: flags.healthcheck,
	}

	emailFileExists := false
	if emailRecipients, err := readEmailFile(defaultEmailFile()); err == nil {
		emailFileExists = true
		fsstate.Email = append(fsstate.Email, emailRecipients...)
	} else if !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "%s: error reading email recipients file %q: %s\n", programName, defaultEmailFile(), err)
		os.Exit(1)
	}

	if len(fsstate.Email) == 0 && !emailFileExists && fsstate.Script == "" && !fileExists(fsstate.ScriptDir) && fsstate.Stdout == false {
		fmt.Fprintf(os.Stderr, "%s: no notification methods were specified\n", programName)
		fmt.Fprintf(os.Stderr, "Please specify at least one of the following notification methods:\n")
		fmt.Fprintf(os.Stderr, " - Place one or more email addresses in %s (one address per line)\n", defaultEmailFile())
		fmt.Fprintf(os.Stderr, " - Place one or more executable scripts in the %s directory\n", fsstate.ScriptDir)
		fmt.Fprintf(os.Stderr, " - Specify an email address using the -email flag\n")
		fmt.Fprintf(os.Stderr, " - Specify the path to an executable script using the -script flag\n")
		fmt.Fprintf(os.Stderr, " - Specify the -stdout flag\n")
		os.Exit(2)
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

	if err := monitor.Run(ctx, config); ctx.Err() == context.Canceled && errors.Is(err, context.Canceled) {
		if flags.verbose {
			fmt.Fprintf(os.Stderr, "%s: exiting due to SIGINT or SIGTERM\n", programName)
		}
		os.Exit(0)
	} else {
		fmt.Fprintf(os.Stderr, "%s: %s\n", programName, err)
		os.Exit(1)
	}
}
