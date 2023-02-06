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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
)

type discoveredCert struct {
	WatchItem    WatchItem
	LogEntry     *logEntry
	Info         *certspotter.CertInfo
	Chain        []ct.ASN1Cert // first entry is the leaf certificate or precertificate
	TBSSHA256    [32]byte      // computed over Info.TBS.Raw
	SHA256       [32]byte      // computed over Chain[0]
	PubkeySHA256 [32]byte      // computed over Info.TBS.PublicKey.FullBytes
	Identifiers  *certspotter.Identifiers
	CertPath     string // empty if not saved on the filesystem
	JSONPath     string // empty if not saved on the filesystem
	TextPath     string // empty if not saved on the filesystem
}

func (cert *discoveredCert) pemChain() []byte {
	var buffer bytes.Buffer
	for _, certBytes := range cert.Chain {
		if err := pem.Encode(&buffer, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		}); err != nil {
			panic(fmt.Errorf("encoding certificate as PEM failed unexpectedly: %w", err))
		}
	}
	return buffer.Bytes()
}

func (cert *discoveredCert) json() []byte {
	object := map[string]any{
		"tbs_sha256":    hex.EncodeToString(cert.TBSSHA256[:]),
		"pubkey_sha256": hex.EncodeToString(cert.PubkeySHA256[:]),
		"dns_names":     cert.Identifiers.DNSNames,
		"ip_addresses":  cert.Identifiers.IPAddrs,
	}

	if cert.Info.ValidityParseError == nil {
		object["not_before"] = cert.Info.Validity.NotBefore
		object["not_after"] = cert.Info.Validity.NotAfter
	} else {
		object["not_before"] = nil
		object["not_after"] = nil
	}

	jsonBytes, err := json.Marshal(object)
	if err != nil {
		panic(fmt.Errorf("encoding certificate as JSON failed unexpectedly: %w", err))
	}
	return jsonBytes
}

func (cert *discoveredCert) save() error {
	if err := writeFile(cert.CertPath, cert.pemChain(), 0666); err != nil {
		return err
	}
	if err := writeFile(cert.JSONPath, cert.json(), 0666); err != nil {
		return err
	}
	if err := writeFile(cert.TextPath, []byte(cert.Text()), 0666); err != nil {
		return err
	}
	return nil
}

func (cert *discoveredCert) Environ() []string {
	env := []string{
		"EVENT=discovered_cert",
		"SUMMARY=certificate discovered for " + cert.WatchItem.String(),
		"CERT_PARSEABLE=yes", // backwards compat with pre-0.15.0; not documented
		"LOG_URI=" + cert.LogEntry.Log.URL,
		"ENTRY_INDEX=" + fmt.Sprint(cert.LogEntry.Index),
		"WATCH_ITEM=" + cert.WatchItem.String(),
		"TBS_SHA256=" + hex.EncodeToString(cert.TBSSHA256[:]),
		"CERT_SHA256=" + hex.EncodeToString(cert.SHA256[:]),
		"FINGERPRINT=" + hex.EncodeToString(cert.SHA256[:]), // backwards compat with pre-0.15.0; not documented
		"PUBKEY_SHA256=" + hex.EncodeToString(cert.PubkeySHA256[:]),
		"PUBKEY_HASH=" + hex.EncodeToString(cert.PubkeySHA256[:]), // backwards compat with pre-0.15.0; not documented
		"CERT_FILENAME=" + cert.CertPath,
		"JSON_FILENAME=" + cert.JSONPath,
		"TEXT_FILENAME=" + cert.TextPath,
	}

	if cert.Info.ValidityParseError == nil {
		env = append(env, "NOT_BEFORE="+cert.Info.Validity.NotBefore.String())
		env = append(env, "NOT_BEFORE_UNIXTIME="+fmt.Sprint(cert.Info.Validity.NotBefore.Unix()))
		env = append(env, "NOT_BEFORE_RFC3339="+cert.Info.Validity.NotBefore.Format(time.RFC3339))
		env = append(env, "NOT_AFTER="+cert.Info.Validity.NotAfter.String())
		env = append(env, "NOT_AFTER_UNIXTIME="+fmt.Sprint(cert.Info.Validity.NotAfter.Unix()))
		env = append(env, "NOT_AFTER_RFC3339="+cert.Info.Validity.NotAfter.Format(time.RFC3339))
	} else {
		env = append(env, "VALIDITY_PARSE_ERROR="+cert.Info.ValidityParseError.Error())
	}

	if cert.Info.SubjectParseError == nil {
		env = append(env, "SUBJECT_DN="+cert.Info.Subject.String())
	} else {
		env = append(env, "SUBJECT_PARSE_ERROR="+cert.Info.SubjectParseError.Error())
	}

	if cert.Info.IssuerParseError == nil {
		env = append(env, "ISSUER_DN="+cert.Info.Issuer.String())
	} else {
		env = append(env, "ISSUER_PARSE_ERROR="+cert.Info.IssuerParseError.Error())
	}

	if cert.Info.SerialNumberParseError == nil {
		env = append(env, "SERIAL="+fmt.Sprintf("%x", cert.Info.SerialNumber))
	} else {
		env = append(env, "SERIAL_PARSE_ERROR="+cert.Info.SerialNumberParseError.Error())
	}

	return env
}

func (cert *discoveredCert) Text() string {
	// TODO-4: improve the output: include WatchItem, indicate hash algorithm used for fingerprints, ... (look at SSLMate email for inspiration)

	text := new(strings.Builder)
	writeField := func(name string, value any) { fmt.Fprintf(text, "\t%13s = %s\n", name, value) }

	fmt.Fprintf(text, "%x:\n", cert.SHA256)
	for _, dnsName := range cert.Identifiers.DNSNames {
		writeField("DNS Name", dnsName)
	}
	for _, ipaddr := range cert.Identifiers.IPAddrs {
		writeField("IP Address", ipaddr)
	}
	writeField("Pubkey", hex.EncodeToString(cert.PubkeySHA256[:]))
	if cert.Info.IssuerParseError == nil {
		writeField("Issuer", cert.Info.Issuer)
	} else {
		writeField("Issuer", fmt.Sprintf("[unable to parse: %s]", cert.Info.IssuerParseError))
	}
	if cert.Info.ValidityParseError == nil {
		writeField("Not Before", cert.Info.Validity.NotBefore)
		writeField("Not After", cert.Info.Validity.NotAfter)
	} else {
		writeField("Not Before", fmt.Sprintf("[unable to parse: %s]", cert.Info.ValidityParseError))
		writeField("Not After", fmt.Sprintf("[unable to parse: %s]", cert.Info.ValidityParseError))
	}
	writeField("Log Entry", fmt.Sprintf("%d @ %s", cert.LogEntry.Index, cert.LogEntry.Log.URL))
	writeField("crt.sh", "https://crt.sh/?sha256="+hex.EncodeToString(cert.SHA256[:]))
	if cert.CertPath != "" {
		writeField("Filename", cert.CertPath)
	}

	return text.String()
}

func (cert *discoveredCert) EmailSubject() string {
	return fmt.Sprintf("[certspotter] Certificate Discovered for %s", cert.WatchItem)
}
