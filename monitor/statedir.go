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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/merkletree"
	"strconv"
	"strings"
	"time"
)

func readVersion(stateDir string) (int, error) {
	path := filepath.Join(stateDir, "version")

	fileBytes, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if fileExists(filepath.Join(stateDir, "evidence")) {
			return 0, nil
		} else {
			return -1, nil
		}
	} else if err != nil {
		return -1, err
	}

	version, err := strconv.Atoi(strings.TrimSpace(string(fileBytes)))
	if err != nil {
		return -1, fmt.Errorf("version file %q is malformed: %w", path, err)
	}

	return version, nil
}

func writeVersion(stateDir string) error {
	return writeFile(filepath.Join(stateDir, "version"), []byte{'2', '\n'}, 0666)
}

func migrateLogStateDirV1(dir string) error {
	var sth ct.SignedTreeHead
	var tree merkletree.CollapsedTree

	sthPath := filepath.Join(dir, "sth.json")
	sthData, err := os.ReadFile(sthPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	treePath := filepath.Join(dir, "tree.json")
	treeData, err := os.ReadFile(treePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	if err := json.Unmarshal(sthData, &sth); err != nil {
		return fmt.Errorf("error unmarshaling %s: %w", sthPath, err)
	}
	if err := json.Unmarshal(treeData, &tree); err != nil {
		return fmt.Errorf("error unmarshaling %s: %w", treePath, err)
	}

	stateFile := stateFile{
		DownloadPosition: &tree,
		VerifiedPosition: &tree,
		VerifiedSTH:      &sth,
		LastSuccess:      time.Now().UTC(),
	}
	if stateFile.store(filepath.Join(dir, "state.json")); err != nil {
		return err
	}

	if err := os.Remove(sthPath); err != nil {
		return err
	}
	if err := os.Remove(treePath); err != nil {
		return err
	}
	return nil
}

func migrateStateDirV1(stateDir string) error {
	if lockfile := filepath.Join(stateDir, "lock"); fileExists(lockfile) {
		return fmt.Errorf("directory is locked by another instance of certspotter; remove %s if this is not the case", lockfile)
	}

	if logDirs, err := os.ReadDir(filepath.Join(stateDir, "logs")); err == nil {
		for _, logDir := range logDirs {
			if strings.HasPrefix(logDir.Name(), ".") || !logDir.IsDir() {
				continue
			}
			if err := migrateLogStateDirV1(filepath.Join(stateDir, "logs", logDir.Name())); err != nil {
				return fmt.Errorf("error migrating log state: %w", err)
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	if err := writeVersion(stateDir); err != nil {
		return err
	}

	if err := os.Remove(filepath.Join(stateDir, "once")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

func prepareStateDir(stateDir string) error {
	if err := os.Mkdir(stateDir, 0777); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}

	if version, err := readVersion(stateDir); err != nil {
		return err
	} else if version == -1 {
		if err := writeVersion(stateDir); err != nil {
			return err
		}
	} else if version == 0 {
		return fmt.Errorf("%s was created by a very old version of certspotter; run any version of certspotter after 0.2 and before 0.15.0 to upgrade this directory, or remove it to start from scratch", stateDir)
	} else if version == 1 {
		if err := migrateStateDirV1(stateDir); err != nil {
			return err
		}
	} else if version > 2 {
		return fmt.Errorf("%s was created by a newer version of certspotter; upgrade to the latest version of certspotter or remove this directory to start from scratch", stateDir)
	}

	for _, subdir := range []string{"certs", "logs", "healthchecks"} {
		if err := os.Mkdir(filepath.Join(stateDir, subdir), 0777); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}

	return nil
}
