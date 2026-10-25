// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package loglist

import (
	"archive/zip"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// Sign creates a signed ZIP archive, in the format documented by [Load].
func Sign(w io.Writer, signer crypto.Signer, basename string, jsonBytes []byte) error {
	digest := sha256.Sum256(jsonBytes)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("error signing log list: %w", err)
	}
	archive := zip.NewWriter(w)
	if err := writeZipFile(archive, basename+".json", jsonBytes); err != nil {
		return err
	}
	if err := writeZipFile(archive, basename+".sig", signature); err != nil {
		return err
	}
	return archive.Close()
}

func writeZipFile(archive *zip.Writer, name string, content []byte) error {
	file, err := archive.Create(name)
	if err != nil {
		return fmt.Errorf("error creating %s in zip archive: %w", name, err)
	}
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("error writing %s to zip archive: %w", name, err)
	}
	return nil
}
