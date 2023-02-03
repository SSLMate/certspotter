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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var stdoutMu sync.Mutex

type notification interface {
	Environ() []string
	EmailSubject() string
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
	fmt.Fprintf(stdin, "Subject: %s\n", notif.EmailSubject())
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

func execScript(ctx context.Context, scriptPath string, notif notification) error {
	// TODO-3: consider removing directory support (for now), and supporting $PATH lookups
	info, err := os.Stat(scriptPath)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("script %q does not exist", scriptPath)
	} else if err != nil {
		return fmt.Errorf("error executing script %q: %w", scriptPath, err)
	} else if info.IsDir() {
		return execScriptDir(ctx, scriptPath, notif)
	} else {
		return execScriptFile(ctx, scriptPath, notif)
	}

}

func execScriptDir(ctx context.Context, dirPath string, notif notification) error {
	dirents, err := os.ReadDir(dirPath)
	if err != nil {
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
			if err := execScriptFile(ctx, scriptPath, notif); err != nil {
				return err
			}
		}
	}
	return nil
}

func execScriptFile(ctx context.Context, scriptPath string, notif notification) error {
	stderr := new(bytes.Buffer)

	cmd := exec.CommandContext(ctx, scriptPath)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, notif.Environ()...)
	cmd.Stderr = stderr

	if err := cmd.Run(); err == nil {
		return nil
	} else if ctx.Err() != nil {
		return ctx.Err()
	} else if exitErr, isExitError := err.(*exec.ExitError); isExitError && exitErr.Exited() {
		return fmt.Errorf("script %q exited with code %d and error %q", scriptPath, exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
	} else if isExitError {
		return fmt.Errorf("script %q terminated by signal with error %q", scriptPath, strings.TrimSpace(stderr.String()))
	} else {
		return fmt.Errorf("error executing script %q: %w", scriptPath, err)
	}
}

func isExecutable(mode os.FileMode) bool {
	return mode&0111 != 0
}
