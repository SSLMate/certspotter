// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter/ct"
)

func ReadSTHFile(path string) (*ct.SignedTreeHead, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var sth ct.SignedTreeHead
	if err := json.Unmarshal(content, &sth); err != nil {
		return nil, err
	}

	return &sth, nil
}

func WriteSTHFile(path string, sth *ct.SignedTreeHead) error {
	sthJson, err := json.MarshalIndent(sth, "", "\t")
	if err != nil {
		return err
	}
	sthJson = append(sthJson, byte('\n'))
	return ioutil.WriteFile(path, sthJson, 0666)
}

func WriteProofFile(path string, proof ct.ConsistencyProof) error {
	proofJson, err := json.MarshalIndent(proof, "", "\t")
	if err != nil {
		return err
	}
	proofJson = append(proofJson, byte('\n'))
	return ioutil.WriteFile(path, proofJson, 0666)
}

func IsPrecert(entry *ct.LogEntry) bool {
	return entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType
}

func GetFullChain(entry *ct.LogEntry) [][]byte {
	certs := make([][]byte, 0, len(entry.Chain)+1)

	if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
		certs = append(certs, entry.Leaf.TimestampedEntry.X509Entry)
	}
	for _, cert := range entry.Chain {
		certs = append(certs, cert)
	}

	return certs
}

func formatSerialNumber(serial *big.Int) string {
	if serial != nil {
		return fmt.Sprintf("%x", serial)
	} else {
		return ""
	}
}

func sha256sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha256hex(data []byte) string {
	return hex.EncodeToString(sha256sum(data))
}

type EntryInfo struct {
	LogUri                string
	Entry                 *ct.LogEntry
	IsPrecert             bool
	FullChain             [][]byte // first entry is logged X509 cert or pre-cert
	CertInfo              *CertInfo
	ParseError            error // set iff CertInfo is nil
	Identifiers           *Identifiers
	IdentifiersParseError error
	Filename              string
	Bygone                bool
}

type CertInfo struct {
	TBS *TBSCertificate

	Subject                RDNSequence
	SubjectParseError      error
	Issuer                 RDNSequence
	IssuerParseError       error
	SANs                   []SubjectAltName
	SANsParseError         error
	SerialNumber           *big.Int
	SerialNumberParseError error
	Validity               *CertValidity
	ValidityParseError     error
	IsCA                   *bool
	IsCAParseError         error
	IsPreCert              bool
}

func MakeCertInfoFromTBS(tbs *TBSCertificate) *CertInfo {
	info := &CertInfo{TBS: tbs}

	info.Subject, info.SubjectParseError = tbs.ParseSubject()
	info.Issuer, info.IssuerParseError = tbs.ParseIssuer()
	info.SANs, info.SANsParseError = tbs.ParseSubjectAltNames()
	info.SerialNumber, info.SerialNumberParseError = tbs.ParseSerialNumber()
	info.Validity, info.ValidityParseError = tbs.ParseValidity()
	info.IsCA, info.IsCAParseError = tbs.ParseBasicConstraints()
	info.IsPreCert = len(tbs.GetExtension(oidExtensionCTPoison)) > 0

	return info
}

func MakeCertInfoFromRawTBS(tbsBytes []byte) (*CertInfo, error) {
	tbs, err := ParseTBSCertificate(tbsBytes)
	if err != nil {
		return nil, err
	}
	return MakeCertInfoFromTBS(tbs), nil
}

func MakeCertInfoFromRawCert(certBytes []byte) (*CertInfo, error) {
	cert, err := ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return MakeCertInfoFromRawTBS(cert.GetRawTBSCertificate())
}

func MakeCertInfoFromLogEntry(entry *ct.LogEntry) (*CertInfo, error) {
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		return MakeCertInfoFromRawCert(entry.Leaf.TimestampedEntry.X509Entry)

	case ct.PrecertLogEntryType:
		return MakeCertInfoFromRawTBS(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)

	default:
		return nil, fmt.Errorf("MakeCertInfoFromCTEntry: unknown CT entry type (neither X509 nor precert)")
	}
}

func (info *CertInfo) NotBefore() *time.Time {
	if info.ValidityParseError == nil {
		return &info.Validity.NotBefore
	} else {
		return nil
	}
}

func (info *CertInfo) NotAfter() *time.Time {
	if info.ValidityParseError == nil {
		return &info.Validity.NotAfter
	} else {
		return nil
	}
}

func (info *CertInfo) PubkeyHash() string {
	return sha256hex(info.TBS.GetRawPublicKey())
}

func (info *CertInfo) PubkeyHashBytes() []byte {
	return sha256sum(info.TBS.GetRawPublicKey())
}

func (info *CertInfo) Environ() []string {
	env := make([]string, 0, 10)

	env = append(env, "PUBKEY_HASH="+info.PubkeyHash())

	if info.SerialNumberParseError != nil {
		env = append(env, "SERIAL_PARSE_ERROR="+info.SerialNumberParseError.Error())
	} else {
		env = append(env, "SERIAL="+formatSerialNumber(info.SerialNumber))
	}

	if info.ValidityParseError != nil {
		env = append(env, "VALIDITY_PARSE_ERROR="+info.ValidityParseError.Error())
	} else {
		env = append(env, "NOT_BEFORE="+info.Validity.NotBefore.String())
		env = append(env, "NOT_BEFORE_UNIXTIME="+strconv.FormatInt(info.Validity.NotBefore.Unix(), 10))
		env = append(env, "NOT_AFTER="+info.Validity.NotAfter.String())
		env = append(env, "NOT_AFTER_UNIXTIME="+strconv.FormatInt(info.Validity.NotAfter.Unix(), 10))
	}

	if info.SubjectParseError != nil {
		env = append(env, "SUBJECT_PARSE_ERROR="+info.SubjectParseError.Error())
	} else {
		env = append(env, "SUBJECT_DN="+info.Subject.String())
	}

	if info.IssuerParseError != nil {
		env = append(env, "ISSUER_PARSE_ERROR="+info.IssuerParseError.Error())
	} else {
		env = append(env, "ISSUER_DN="+info.Issuer.String())
	}

	// TODO: include SANs in environment

	return env
}

func (info *EntryInfo) HasParseErrors() bool {
	return info.ParseError != nil ||
		info.IdentifiersParseError != nil ||
		info.CertInfo.SubjectParseError != nil ||
		info.CertInfo.IssuerParseError != nil ||
		info.CertInfo.SANsParseError != nil ||
		info.CertInfo.SerialNumberParseError != nil ||
		info.CertInfo.ValidityParseError != nil ||
		info.CertInfo.IsCAParseError != nil
}

func (info *EntryInfo) Fingerprint() string {
	if len(info.FullChain) > 0 {
		return sha256hex(info.FullChain[0])
	} else {
		return ""
	}
}

func (info *EntryInfo) FingerprintBytes() []byte {
	if len(info.FullChain) > 0 {
		return sha256sum(info.FullChain[0])
	} else {
		return []byte{}
	}
}

func (info *EntryInfo) typeString() string {
	if info.IsPrecert {
		return "precert"
	} else {
		return "cert"
	}
}

func (info *EntryInfo) typeFriendlyString() string {
	if info.IsPrecert {
		return "Pre-certificate"
	} else {
		return "Certificate"
	}
}

func yesnoString(value bool) string {
	if value {
		return "yes"
	} else {
		return "no"
	}
}

func (info *EntryInfo) Environ() []string {
	env := []string{
		"FINGERPRINT=" + info.Fingerprint(),
		"CERT_TYPE=" + info.typeString(),
		"CERT_PARSEABLE=" + yesnoString(info.ParseError == nil),
		"LOG_URI=" + info.LogUri,
		"ENTRY_INDEX=" + strconv.FormatInt(info.Entry.Index, 10),
	}

	if info.Filename != "" {
		env = append(env, "CERT_FILENAME="+info.Filename)
	}
	if info.ParseError != nil {
		env = append(env, "PARSE_ERROR="+info.ParseError.Error())
	} else if info.CertInfo != nil {
		certEnv := info.CertInfo.Environ()
		env = append(env, certEnv...)
	}
	if info.IdentifiersParseError != nil {
		env = append(env, "IDENTIFIERS_PARSE_ERROR="+info.IdentifiersParseError.Error())
	} else if info.Identifiers != nil {
		env = append(env, "DNS_NAMES="+info.Identifiers.dnsNamesString(","))
		env = append(env, "IP_ADDRESSES="+info.Identifiers.ipAddrsString(","))
	}

	return env
}

func writeField(out io.Writer, name string, value interface{}, err error) {
	if err == nil {
		fmt.Fprintf(out, "\t%13s = %s\n", name, value)
	} else {
		fmt.Fprintf(out, "\t%13s = *** UNKNOWN (%s) ***\n", name, err)
	}
}

func (info *EntryInfo) Write(out io.Writer) {
	fingerprint := info.Fingerprint()
	fmt.Fprintf(out, "%s:\n", fingerprint)
	if info.IdentifiersParseError != nil {
		writeField(out, "Identifiers", nil, info.IdentifiersParseError)
	} else if info.Identifiers != nil {
		for _, dnsName := range info.Identifiers.DNSNames {
			writeField(out, "DNS Name", dnsName, nil)
		}
		for _, ipaddr := range info.Identifiers.IPAddrs {
			writeField(out, "IP Address", ipaddr, nil)
		}
	}
	if info.ParseError != nil {
		writeField(out, "Parse Error", "*** "+info.ParseError.Error()+" ***", nil)
	} else if info.CertInfo != nil {
		writeField(out, "Pubkey", info.CertInfo.PubkeyHash(), nil)
		writeField(out, "Issuer", info.CertInfo.Issuer, info.CertInfo.IssuerParseError)
		writeField(out, "Not Before", info.CertInfo.NotBefore(), info.CertInfo.ValidityParseError)
		writeField(out, "Not After", info.CertInfo.NotAfter(), info.CertInfo.ValidityParseError)
		if info.Bygone {
			writeField(out, "BygoneSSL", "True", info.CertInfo.ValidityParseError)
		}
	}
	writeField(out, "Log Entry", fmt.Sprintf("%d @ %s (%s)", info.Entry.Index, info.LogUri, info.typeFriendlyString()), nil)
	writeField(out, "crt.sh", "https://crt.sh/?sha256="+fingerprint, nil)
	if info.Filename != "" {
		writeField(out, "Filename", info.Filename, nil)
	}
}

func (info *EntryInfo) InvokeHookScript(command string) error {
	cmd := exec.Command(command)
	cmd.Env = os.Environ()
	infoEnv := info.Environ()
	cmd.Env = append(cmd.Env, infoEnv...)
	stderrBuffer := bytes.Buffer{}
	cmd.Stderr = &stderrBuffer
	if err := cmd.Run(); err != nil {
		if _, isExitError := err.(*exec.ExitError); isExitError {
			return fmt.Errorf("Script failed: %s: %s", command, strings.TrimSpace(stderrBuffer.String()))
		} else {
			return fmt.Errorf("Failed to execute script: %s: %s", command, err)
		}
	}
	return nil
}

func MatchesWildcard(dnsName string, pattern string) bool {
	for len(pattern) > 0 {
		if pattern[0] == '*' {
			if len(dnsName) > 0 && dnsName[0] != '.' && MatchesWildcard(dnsName[1:], pattern) {
				return true
			}
			pattern = pattern[1:]
		} else {
			if len(dnsName) == 0 || pattern[0] != dnsName[0] {
				return false
			}
			pattern = pattern[1:]
			dnsName = dnsName[1:]
		}
	}
	return len(dnsName) == 0
}
