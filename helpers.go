package ctwatch

import (
	"fmt"
	"time"
	"os"
	"os/exec"
	"bytes"
	"io"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"encoding/json"

	"src.agwa.name/ctwatch/ct"
)

func ReadSTHFile (path string) (*ct.SignedTreeHead, error) {
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

func WriteSTHFile (path string, sth *ct.SignedTreeHead) error {
	sthJson, err := json.MarshalIndent(sth, "", "\t")
	if err != nil {
		return err
	}
	sthJson = append(sthJson, byte('\n'))
	return ioutil.WriteFile(path, sthJson, 0666)
}

func IsPrecert (entry *ct.LogEntry) bool {
	return entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType
}

func GetFullChain (entry *ct.LogEntry) [][]byte {
	certs := make([][]byte, 0, len(entry.Chain) + 1)

	if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
		certs = append(certs, entry.Leaf.TimestampedEntry.X509Entry)
	}
	for _, cert := range entry.Chain {
		certs = append(certs, cert)
	}

	return certs
}

func formatSerialNumber (serial *big.Int) string {
	if serial != nil {
		return fmt.Sprintf("%x", serial)
	} else {
		return ""
	}
}

func sha256hex (data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type EntryInfo struct {
	LogUri			string
	Entry			*ct.LogEntry
	IsPrecert		bool
	FullChain		[][]byte	// first entry is logged X509 cert or pre-cert
	CertInfo		*CertInfo
	ParseError		error		// set iff CertInfo is nil
	Filename		string
}

type CertInfo struct {
	TBS			*TBSCertificate

	DNSNames		[]string
	DNSNamesParseError	error
	Subject			RDNSequence
	SubjectParseError	error
	Issuer			RDNSequence
	IssuerParseError	error
	SerialNumber		*big.Int
	SerialNumberParseError	error
	Validity		*CertValidity
	ValidityParseError	error
	Constraints		*BasicConstraints
	ConstraintsParseError	error
}

func MakeCertInfoFromTBS (tbs *TBSCertificate) *CertInfo {
	info := &CertInfo{TBS: tbs}

	info.DNSNames, info.DNSNamesParseError = tbs.ParseDNSNames()
	info.Subject, info.SubjectParseError = tbs.ParseSubject()
	info.Issuer, info.IssuerParseError = tbs.ParseIssuer()
	info.SerialNumber, info.SerialNumberParseError = tbs.ParseSerialNumber()
	info.Validity, info.ValidityParseError = tbs.ParseValidity()
	info.Constraints, info.ConstraintsParseError = tbs.ParseBasicConstraints()

	return info
}

func MakeCertInfoFromRawTBS (tbsBytes []byte) (*CertInfo, error) {
	tbs, err := ParseTBSCertificate(tbsBytes)
	if err != nil {
		return nil, err
	}
	return MakeCertInfoFromTBS(tbs), nil
}

func MakeCertInfoFromRawCert (certBytes []byte) (*CertInfo, error) {
	cert, err := ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return MakeCertInfoFromRawTBS(cert.GetRawTBSCertificate())
}

func MakeCertInfo (entry *ct.LogEntry) (*CertInfo, error) {
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		return MakeCertInfoFromRawCert(entry.Leaf.TimestampedEntry.X509Entry)

	case ct.PrecertLogEntryType:
		return MakeCertInfoFromRawTBS(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)

	default:
		return nil, fmt.Errorf("MakeCertInfoFromCTEntry: unknown CT entry type (neither X509 nor precert)")
	}
}

func (info *CertInfo) dnsNamesString () string {
	if info.DNSNamesParseError == nil {
		return strings.Join(info.DNSNames, ", ")
	} else {
		return ""
	}
}

func (info *CertInfo) NotBefore () *time.Time {
	if info.ValidityParseError == nil {
		return &info.Validity.NotBefore
	} else {
		return nil
	}
}

func (info *CertInfo) NotAfter () *time.Time {
	if info.ValidityParseError == nil {
		return &info.Validity.NotAfter
	} else {
		return nil
	}
}

func (info *CertInfo) PubkeyHash () string {
	return sha256hex(info.TBS.GetRawPublicKey())
}

func (info *CertInfo) Environ () []string {
	env := make([]string, 0, 10)

	env = append(env, "PUBKEY_HASH=" + info.PubkeyHash())

	if info.DNSNamesParseError != nil {
		env = append(env, "DNS_NAMES_PARSE_ERROR=" + info.DNSNamesParseError.Error())
	} else {
		env = append(env, "DNS_NAMES=" + strings.Join(info.DNSNames, ","))
	}

	if info.SerialNumberParseError != nil {
		env = append(env, "SERIAL_PARSE_ERROR=" + info.SerialNumberParseError.Error())
	} else {
		env = append(env, "SERIAL=" + formatSerialNumber(info.SerialNumber))
	}

	if info.ValidityParseError != nil {
		env = append(env, "VALIDITY_PARSE_ERROR=" + info.ValidityParseError.Error())
	} else {
		env = append(env, "NOT_BEFORE=" + info.Validity.NotBefore.String())
		env = append(env, "NOT_BEFORE_UNIXTIME=" + strconv.FormatInt(info.Validity.NotBefore.Unix(), 10))
		env = append(env, "NOT_AFTER=" + info.Validity.NotAfter.String())
		env = append(env, "NOT_AFTER_UNIXTIME=" + strconv.FormatInt(info.Validity.NotAfter.Unix(), 10))
	}

	if info.SubjectParseError != nil {
		env = append(env, "SUBJECT_PARSE_ERROR=" + info.SubjectParseError.Error())
	} else {
		env = append(env, "SUBJECT_DN=" + info.Subject.String())
	}

	if info.IssuerParseError != nil {
		env = append(env, "ISSUER_PARSE_ERROR=" + info.IssuerParseError.Error())
	} else {
		env = append(env, "ISSUER_DN=" + info.Issuer.String())
	}

	return env
}

func (info *EntryInfo) Fingerprint () string {
	if len(info.FullChain) > 0 {
		return sha256hex(info.FullChain[0])
	} else {
		return ""
	}
}

func (info *EntryInfo) typeString () string {
	if info.IsPrecert {
		return "precert"
	} else {
		return "cert"
	}
}

func (info *EntryInfo) typeFriendlyString () string {
	if info.IsPrecert {
		return "Pre-certificate"
	} else {
		return "Certificate"
	}
}

func yesnoString (value bool) string {
	if value {
		return "yes"
	} else {
		return "no"
	}
}

func (info *EntryInfo) Environ () []string {
	env := []string{
		"FINGERPRINT=" + info.Fingerprint(),
		"CERT_TYPE=" + info.typeString(),
		"CERT_PARSEABLE=" + yesnoString(info.ParseError == nil),
		"LOG_URI=" + info.LogUri,
		"ENTRY_INDEX=" + strconv.FormatInt(info.Entry.Index, 10),
	}

	if info.Filename != "" {
		env = append(env, "CERT_FILENAME=" + info.Filename)
	}
	if info.ParseError == nil {
		certEnv := info.CertInfo.Environ()
		env = append(env, certEnv...)
	} else {
		env = append(env, "PARSE_ERROR=" + info.ParseError.Error())
	}

	return env
}

func writeField (out io.Writer, name string, value interface{}, err error) {
	if err == nil {
		fmt.Fprintf(out, "\t%13s = %s\n", name, value)
	} else {
		fmt.Fprintf(out, "\t%13s = *** UNKNOWN (%s) ***\n", name, err)
	}
}

func (info *EntryInfo) Write (out io.Writer) {
	fingerprint := info.Fingerprint()
	fmt.Fprintf(out, "%s:\n", fingerprint)
	if info.ParseError != nil {
		writeField(out, "Parse Error", "*** " + info.ParseError.Error() + " ***", nil)
	} else {
		writeField(out, "DNS Names", info.CertInfo.dnsNamesString(), info.CertInfo.DNSNamesParseError)
		writeField(out, "Pubkey", info.CertInfo.PubkeyHash(), nil)
		writeField(out, "Subject", info.CertInfo.Subject, info.CertInfo.SubjectParseError)
		writeField(out, "Issuer", info.CertInfo.Issuer, info.CertInfo.IssuerParseError)
		writeField(out, "Serial", info.CertInfo.SerialNumber, info.CertInfo.SerialNumberParseError)
		writeField(out, "Not Before", info.CertInfo.NotBefore(), info.CertInfo.ValidityParseError)
		writeField(out, "Not After", info.CertInfo.NotAfter(), info.CertInfo.ValidityParseError)
	}
	writeField(out, "Type", info.typeFriendlyString(), nil)
	writeField(out, "Log Entry", fmt.Sprintf("%d @ %s", info.Entry.Index, info.LogUri), nil)
	writeField(out, "crt.sh", "https://crt.sh/?q=" + fingerprint, nil)
	if info.Filename != "" {
		writeField(out, "Filename", info.Filename, nil)
	}
}

func (info *EntryInfo) InvokeHookScript (command string) error {
	cmd := exec.Command(command)
	cmd.Env = os.Environ()
	infoEnv := info.Environ()
	cmd.Env = append(cmd.Env, infoEnv...)
	stderrBuffer := bytes.Buffer{}
	cmd.Stderr = &stderrBuffer
	if err := cmd.Run(); err != nil {
		if _, isExitError := err.(*exec.ExitError); isExitError {
			fmt.Errorf("Script failed: %s: %s", command, strings.TrimSpace(stderrBuffer.String()))
		} else {
			fmt.Errorf("Failed to execute script: %s: %s", command, err)
		}
	}
	return nil
}

func WriteCertRepository (repoPath string, isPrecert bool, certs [][]byte) (bool, string, error) {
	if len(certs) == 0 {
		return false, "", fmt.Errorf("Cannot write an empty certificate chain")
	}

	fingerprint := sha256hex(certs[0])
	prefixPath := filepath.Join(repoPath, fingerprint[0:2])
	var filenameSuffix string
	if isPrecert {
		filenameSuffix = ".precert.pem"
	} else {
		filenameSuffix = ".cert.pem"
	}
	if err := os.Mkdir(prefixPath, 0777); err != nil && !os.IsExist(err) {
		return false, "", fmt.Errorf("Failed to create prefix directory %s: %s", prefixPath, err)
	}
	path := filepath.Join(prefixPath, fingerprint + filenameSuffix)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return true, path, nil
		} else {
			return false, path, fmt.Errorf("Failed to open %s for writing: %s", path, err)
		}
	}
	for _, cert := range certs {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			file.Close()
			return false, path, fmt.Errorf("Error writing to %s: %s", path, err)
		}
	}
	if err := file.Close(); err != nil {
		return false, path, fmt.Errorf("Error writing to %s: %s", path, err)
	}

	return false, path, nil
}
