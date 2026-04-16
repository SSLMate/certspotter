// Copyright (C) 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Exit code 75 (EX_TEMPFAIL) from sendmail(1) indicates a transient
// failure, typically that the local MTA is unreachable.
const sendmailExTempFail = 75

// sendmailTempFailRetryDelays gives the wait between sendmail retries
// after an EX_TEMPFAIL.  The last entry is reused indefinitely, so
// certspotter keeps running (and doesn't lose any entries) across
// extended MTA outages and delivers pending notifications once the
// MTA comes back.
var sendmailTempFailRetryDelays = []time.Duration{
	30 * time.Second,
	1 * time.Minute,
	2 * time.Minute,
	5 * time.Minute,
}

var stdoutMu sync.Mutex

type notification struct {
	environ []string
	summary string
	text    string
}

func (s *FilesystemState) notify(ctx context.Context, notif *notification) error {
	if s.Stdout {
		writeToStdout(notif)
	}

	// Run each channel in turn and collect (not short-circuit on) errors,
	// and run email last because it can block for a long time retrying
	// on a down MTA — running it last means script/hooks still fire
	// promptly while email waits for the MTA to come back.
	var errs []error
	if s.Script != "" {
		if err := execScript(ctx, s.Script, notif); err != nil {
			errs = append(errs, err)
		}
	}
	if s.ScriptDir != "" {
		if err := execScriptDir(ctx, s.ScriptDir, notif); err != nil {
			errs = append(errs, err)
		}
	}
	if len(s.Email) > 0 {
		if err := sendEmail(ctx, s.Email, notif); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func writeToStdout(notif *notification) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	os.Stdout.WriteString(notif.text + "\n")
}

func sendEmail(ctx context.Context, to []string, notif *notification) error {
	from := os.Getenv("EMAIL")

	stdin := new(bytes.Buffer)
	if from != "" {
		fmt.Fprintf(stdin, "From: %s\n", from)
	}
	fmt.Fprintf(stdin, "To: %s\n", strings.Join(to, ", "))
	fmt.Fprintf(stdin, "Subject: [certspotter] %s\n", notif.summary)
	fmt.Fprintf(stdin, "Date: %s\n", time.Now().Format(mailDateFormat))
	fmt.Fprintf(stdin, "Message-ID: <%s>\n", generateMessageID())
	fmt.Fprintf(stdin, "Mime-Version: 1.0\n")
	fmt.Fprintf(stdin, "Content-Type: text/plain; charset=US-ASCII\n")
	fmt.Fprintf(stdin, "X-Mailer: certspotter\n")
	fmt.Fprintf(stdin, "\n")
	fmt.Fprint(stdin, notif.text)
	msg := stdin.Bytes()

	args := []string{"-i"}
	if from != "" {
		args = append(args, "-f", from)
	}
	args = append(args, "--")
	args = append(args, to...)

	for attempt := 0; ; attempt++ {
		err := runSendmail(ctx, args, msg, to)
		var tempFail sendmailTempFailError
		if !errors.As(err, &tempFail) {
			return err
		}
		delay := sendmailTempFailRetryDelays[min(attempt, len(sendmailTempFailRetryDelays)-1)]
		log.Printf("sendmail reported temporary failure (exit %d): %s; retrying in %s", sendmailExTempFail, tempFail.stderr, delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

type sendmailTempFailError struct {
	to     []string
	stderr string
}

func (e sendmailTempFailError) Error() string {
	return fmt.Sprintf("error sending email to %v: sendmail failed with exit code %d and error %q", e.to, sendmailExTempFail, e.stderr)
}

func runSendmail(ctx context.Context, args []string, msg []byte, to []string) error {
	stderr := new(bytes.Buffer)

	sendmailCtx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Minute))
	defer cancel()
	sendmail := exec.CommandContext(sendmailCtx, sendmailPath(), args...)
	sendmail.Stdin = bytes.NewReader(msg)
	sendmail.Stderr = stderr
	sendmail.WaitDelay = 5 * time.Second

	err := sendmail.Run()
	if err == nil || err == exec.ErrWaitDelay {
		return nil
	} else if sendmailCtx.Err() != nil && ctx.Err() == nil {
		return fmt.Errorf("error sending email to %v: sendmail command timed out", to)
	} else if ctx.Err() != nil {
		// if the context was canceled, we can't be sure that the error is the fault of sendmail, so ignore it
		return ctx.Err()
	} else if exitErr, isExitError := err.(*exec.ExitError); isExitError && exitErr.Exited() {
		if exitErr.ExitCode() == sendmailExTempFail {
			return sendmailTempFailError{to: to, stderr: strings.TrimSpace(stderr.String())}
		}
		return fmt.Errorf("error sending email to %v: sendmail failed with exit code %d and error %q", to, exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
	} else if isExitError {
		return fmt.Errorf("error sending email to %v: sendmail terminated by signal with error %q", to, strings.TrimSpace(stderr.String()))
	} else {
		return fmt.Errorf("error sending email to %v: error running sendmail command: %w", to, err)
	}
}

func execScript(ctx context.Context, scriptName string, notif *notification) error {
	stderr := new(bytes.Buffer)

	cmd := exec.CommandContext(ctx, scriptName)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, notif.environ...)
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Run(); err == nil || err == exec.ErrWaitDelay {
		return nil
	} else if ctx.Err() != nil {
		// if the context was canceled, we can't be sure that the error is the fault of the script, so ignore it
		return ctx.Err()
	} else if exitErr, isExitError := err.(*exec.ExitError); isExitError && exitErr.Exited() {
		return fmt.Errorf("script %q exited with code %d and error %q", scriptName, exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
	} else if isExitError {
		return fmt.Errorf("script %q terminated by signal with error %q", scriptName, strings.TrimSpace(stderr.String()))
	} else {
		return fmt.Errorf("error executing script: %w", err)
	}
}

func execScriptDir(ctx context.Context, dirPath string, notif *notification) error {
	dirents, err := os.ReadDir(dirPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("error executing scripts in directory %q: %w", dirPath, err)
	}
	for _, dirent := range dirents {
		if strings.HasPrefix(dirent.Name(), ".") {
			continue
		}
		scriptPath := filepath.Join(dirPath, dirent.Name())
		info, err := os.Stat(scriptPath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("error executing %q in directory %q: %w", dirent.Name(), dirPath, err)
		} else if info.Mode().IsRegular() && isExecutable(info.Mode()) {
			if err := execScript(ctx, scriptPath, notif); err != nil {
				return err
			}
		}
	}
	return nil
}

func isExecutable(mode os.FileMode) bool {
	return mode&0111 != 0
}
