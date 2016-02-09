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

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/x509"
	"github.com/google/certificate-transparency/go/x509/pkix"
)

func ReadStateFile (path string) (int64, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, nil
		}
		return -1, err
	}

	startIndex, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
	if err != nil {
		return -1, err
	}

	return startIndex, nil
}

func WriteStateFile (path string, endIndex int64) error {
	return ioutil.WriteFile(path, []byte(strconv.FormatInt(endIndex, 10) + "\n"), 0666)
}

func EntryDNSNames (entry *ct.LogEntry) ([]string, error) {
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		return ExtractDNSNames(entry.Leaf.TimestampedEntry.X509Entry)
	case ct.PrecertLogEntryType:
		return ExtractDNSNamesFromTBS(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
	}
	panic("EntryDNSNames: entry is neither precert nor x509")
}

func ParseEntryCertificate (entry *ct.LogEntry) (*x509.Certificate, error) {
	if entry.Precert != nil {
		// already parsed
		return &entry.Precert.TBSCertificate, nil
	} else if entry.X509Cert != nil {
		// already parsed
		return entry.X509Cert, nil
	} else if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
		return x509.ParseTBSCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
	} else if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
		return x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry)
	} else {
		panic("ParseEntryCertificate: entry is neither precert nor x509")
	}
}

func appendDnArray (buf *bytes.Buffer, code string, values []string) {
	for _, value := range values {
		if buf.Len() != 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(code)
		buf.WriteString("=")
		buf.WriteString(value)
	}
}

func appendDnValue (buf *bytes.Buffer, code string, value string) {
	if value != "" {
		appendDnArray(buf, code, []string{value})
	}
}

func formatDN (name pkix.Name) (string) {
	// C=US, ST=UT, L=Salt Lake City, O=The USERTRUST Network, OU=http://www.usertrust.com, CN=UTN-USERFirst-Hardware
	var buf bytes.Buffer
	appendDnArray(&buf, "C", name.Country)
	appendDnArray(&buf, "ST", name.Province)
	appendDnArray(&buf, "L", name.Locality)
	appendDnArray(&buf, "O", name.Organization)
	appendDnArray(&buf, "OU", name.OrganizationalUnit)
	appendDnValue(&buf, "CN", name.CommonName)
	return buf.String()
}

func allDNSNames (cert *x509.Certificate) []string {
	dnsNames := []string{}

	if cert.Subject.CommonName != "" {
		dnsNames = append(dnsNames, cert.Subject.CommonName)
	}

	for _, dnsName := range cert.DNSNames {
		if dnsName != cert.Subject.CommonName {
			dnsNames = append(dnsNames, dnsName)
		}
	}

	return dnsNames
}

func formatSerial (serial *big.Int) string {
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

func GetRawCert (entry *ct.LogEntry) []byte {
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		return entry.Leaf.TimestampedEntry.X509Entry
	case ct.PrecertLogEntryType:
		return entry.Chain[0]
	}
	panic("GetRawCert: entry is neither precert nor x509")
}

func IsPrecert (entry *ct.LogEntry) bool {
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.PrecertLogEntryType:
		return true
	case ct.X509LogEntryType:
		return false
	}
	panic("IsPrecert: entry is neither precert nor x509")
}

type EntryInfo struct {
	LogUri		string
	Entry		*ct.LogEntry
	ParsedCert	*x509.Certificate
	ParseError	error
	CertInfo	CertInfo
	Filename	string
}

type CertInfo struct {
	DnsNames	[]string
	SubjectDn	string
	IssuerDn	string
	Serial		string
	PubkeyHash	string
	NotBefore	*time.Time
	NotAfter	*time.Time
}

func MakeCertInfo (cert *x509.Certificate) CertInfo {
	return CertInfo {
		DnsNames:	allDNSNames(cert),
		SubjectDn:	formatDN(cert.Subject),
		IssuerDn:	formatDN(cert.Issuer),
		Serial:		formatSerial(cert.SerialNumber),
		PubkeyHash:	sha256hex(cert.RawSubjectPublicKeyInfo),
		NotBefore:	&cert.NotBefore,
		NotAfter:	&cert.NotAfter,
	}
}

func (info *CertInfo) dnsNamesFriendlyString () string {
	if info.DnsNames != nil {
		return strings.Join(info.DnsNames, ", ")
	} else {
		return "*** UNKNOWN ***"
	}
}

func (info *CertInfo) Environ () []string {
	var env []string
	if info.DnsNames != nil   { env = append(env, "DNS_NAMES=" + strings.Join(info.DnsNames, ",")) }
	if info.SubjectDn != ""   { env = append(env, "SUBJECT_DN=" + info.SubjectDn) }
	if info.IssuerDn != ""    { env = append(env, "ISSUER_DN=" + info.IssuerDn) }
	if info.Serial != ""      { env = append(env, "SERIAL=" + info.Serial) }
	if info.PubkeyHash != ""  { env = append(env, "PUBKEY_HASH=" + info.PubkeyHash) }
	if info.NotBefore != nil  { env = append(env, "NOT_BEFORE=" + strconv.FormatInt(info.NotBefore.Unix(), 10)) }
	if info.NotAfter != nil   { env = append(env, "NOT_AFTER=" + strconv.FormatInt(info.NotAfter.Unix(), 10)) }
	return env
}

func (info *EntryInfo) GetRawCert () []byte {
	return GetRawCert(info.Entry)
}

func (info *EntryInfo) Fingerprint () string {
	return sha256hex(info.GetRawCert())
}

func (info *EntryInfo) IsPrecert () bool {
	return IsPrecert(info.Entry)
}

func (info *EntryInfo) typeString () string {
	if info.IsPrecert() {
		return "precert"
	} else {
		return "cert"
	}
}

func (info *EntryInfo) typeFriendlyString () string {
	if info.IsPrecert() {
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
		"CERT_PARSEABLE=" + yesnoString(info.ParsedCert != nil),
		"LOG_URI=" + info.LogUri,
		"ENTRY_INDEX=" + strconv.FormatInt(info.Entry.Index, 10),
	}

	if info.Filename != "" {
		env = append(env, "CERT_FILENAME=" + info.Filename)
	}
	if info.ParseError != nil {
		env = append(env, "PARSE_ERROR=" + info.ParseError.Error())
	}

	certEnv := info.CertInfo.Environ()
	env = append(env, certEnv...)

	return env
}

func (info *EntryInfo) Write (out io.Writer) {
	fingerprint := info.Fingerprint()
	fmt.Fprintf(out, "%s:\n", fingerprint)
	if info.ParseError != nil {
		if info.ParsedCert != nil {
			fmt.Fprintf(out, "\tParse Warning = *** %s ***\n", info.ParseError)
		} else {
			fmt.Fprintf(out, "\t  Parse Error = *** %s ***\n", info.ParseError)
		}
	}
	fmt.Fprintf(out, "\t    DNS Names = %s\n", info.CertInfo.dnsNamesFriendlyString())
	if info.CertInfo.PubkeyHash != "" { fmt.Fprintf(out, "\t       Pubkey = %s\n", info.CertInfo.PubkeyHash) }
	if info.CertInfo.SubjectDn != ""  { fmt.Fprintf(out, "\t      Subject = %s\n", info.CertInfo.SubjectDn) }
	if info.CertInfo.IssuerDn != ""   { fmt.Fprintf(out, "\t       Issuer = %s\n", info.CertInfo.IssuerDn) }
	if info.CertInfo.Serial != ""     { fmt.Fprintf(out, "\t       Serial = %s\n", info.CertInfo.Serial) }
	if info.CertInfo.NotBefore != nil { fmt.Fprintf(out, "\t   Not Before = %s\n", *info.CertInfo.NotBefore) }
	if info.CertInfo.NotAfter != nil  { fmt.Fprintf(out, "\t    Not After = %s\n", *info.CertInfo.NotAfter) }
	fmt.Fprintf(out, "\t         Type = %s\n", info.typeFriendlyString())
	fmt.Fprintf(out, "\t    Log Entry = %d @ %s\n", info.Entry.Index, info.LogUri)
	fmt.Fprintf(out, "\t       crt.sh = https://crt.sh/?q=%s\n", fingerprint)
	if info.Filename != ""            { fmt.Fprintf(out, "\t     Filename = %s\n", info.Filename) }
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

func WriteCertRepository (repoPath string, entry *ct.LogEntry) (bool, string, error) {
	fingerprint := sha256hex(GetRawCert(entry))
	prefixPath := filepath.Join(repoPath, fingerprint[0:2])
	var filenameSuffix string
	if entry.Leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
		filenameSuffix = ".precert.pem"
	} else if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
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
	if entry.Leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: entry.Leaf.TimestampedEntry.X509Entry}); err != nil {
			file.Close()
			return false, path, fmt.Errorf("Error writing to %s: %s", path, err)
		}
	}
	for _, chainCert := range entry.Chain {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: chainCert}); err != nil {
			file.Close()
			return false, path, fmt.Errorf("Error writing to %s: %s", path, err)
		}
	}
	if err := file.Close(); err != nil {
		return false, path, fmt.Errorf("Error writing to %s: %s", path, err)
	}

	return false, path, nil
}
