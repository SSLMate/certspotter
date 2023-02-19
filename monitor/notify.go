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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var stdoutMu sync.Mutex

type notification interface {
	Environ() []string
	Summary() string
	Text() string
}

func notify(ctx context.Context, config *Config, notif notification) error {
	if config.Stdout {
		writeToStdout(notif)
	}

	if len(config.Email) > 0 {
		if err := sendEmail(ctx, config.Email, notif); err != nil {
			return err
		}
	}

	if config.Script != "" {
		if err := execScript(ctx, config.Script, notif); err != nil {
			return err
		}
	}

	return nil
}

func writeToStdout(notif notification) {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	os.Stdout.WriteString(notif.Text() + "\n")
}

func sendEmail(ctx context.Context, to []string, notif notification) error {
	stdin := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	fmt.Fprintf(stdin, "To: %s\n", strings.Join(to, ", "))
	fmt.Fprintf(stdin, "Subject: [certspotter] %s\n", notif.Summary())
	fmt.Fprintf(stdin, "Mime-Version: 1.0\n")
	fmt.Fprintf(stdin, "Content-Type: text/plain; charset=US-ASCII\n")
	fmt.Fprintf(stdin, "X-Mailer: certspotter\n")
	fmt.Fprintf(stdin, "\n")
	fmt.Fprint(stdin, notif.Text())

	args := []string{"-i", "--"}
	args = append(args, to...)

	sendmail := exec.CommandContext(ctx, "/usr/sbin/sendmail", args...)
	sendmail.Stdin = stdin
	sendmail.Stderr = stderr

	if err := sendmail.Run(); err == nil {
		return nil
	} else if ctx.Err() != nil {
		return ctx.Err()
	} else if exitErr, isExitError := err.(*exec.ExitError); isExitError && exitErr.Exited() {
		return fmt.Errorf("error sending email to %v: sendmail failed with exit code %d and error %q", to, exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
	} else {
		return fmt.Errorf("error sending email to %v: %w", to, err)
	}
}

func execScript(ctx context.Context, scriptName string, notif notification) error {
	stderr := new(bytes.Buffer)

	cmd := exec.CommandContext(ctx, scriptName)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, notif.Environ()...)
	cmd.Stderr = stderr

	if err := cmd.Run(); err == nil {
		return nil
	} else if ctx.Err() != nil {
		return ctx.Err()
	} else if exitErr, isExitError := err.(*exec.ExitError); isExitError && exitErr.Exited() {
		return fmt.Errorf("script %q exited with code %d and error %q", scriptName, exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
	} else if isExitError {
		return fmt.Errorf("script %q terminated by signal with error %q", scriptName, strings.TrimSpace(stderr.String()))
	} else {
		return fmt.Errorf("error executing script: %w", err)
	}
}

func isExecutable(mode os.FileMode) bool {
	return mode&0111 != 0
}
