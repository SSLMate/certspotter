package ctwatch

import (
	"fmt"
	"log"
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

func isNonFatalError (err error) bool {
	switch err.(type) {
	case x509.NonFatalErrors:
		return true
	default:
		return false
	}
}

func getRoot (chain []ct.ASN1Cert) *x509.Certificate {
	if len(chain) > 0 {
		root, err := x509.ParseCertificate(chain[len(chain)-1])
		if err == nil || isNonFatalError(err) {
			return root
		}
		log.Printf("Failed to parse root certificate: %s", err)
	}
	return nil
}

func getSubjectOrganization (cert *x509.Certificate) string {
	if cert != nil && len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return ""
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

func getRaw (entry *ct.LogEntry) []byte {
	if entry.Precert != nil {
		return entry.Precert.Raw
	} else if entry.X509Cert != nil {
		return entry.X509Cert.Raw
	} else {
		panic("getRaw: entry is neither precert nor x509")
	}
}

type certInfo struct {
	IsPrecert	bool
	RootOrg		string
	SubjectDn	string
	IssuerDn	string
	DnsNames	[]string
	Serial		string
	PubkeyHash	string
	Fingerprint	string
	NotBefore	time.Time
	NotAfter	time.Time
}

func makeCertInfo (entry *ct.LogEntry) certInfo {
	var isPrecert bool
	var cert *x509.Certificate

	if entry.Precert != nil {
		isPrecert = true
		cert = &entry.Precert.TBSCertificate
	} else if entry.X509Cert != nil {
		isPrecert = false
		cert = entry.X509Cert
	} else {
		panic("makeCertInfo: entry is neither precert nor x509")
	}
	return certInfo {
		IsPrecert:	isPrecert,
		RootOrg:	getSubjectOrganization(getRoot(entry.Chain)),
		SubjectDn:	formatDN(cert.Subject),
		IssuerDn:	formatDN(cert.Issuer),
		DnsNames:	allDNSNames(cert),
		Serial:		formatSerial(cert.SerialNumber),
		PubkeyHash:	sha256hex(cert.RawSubjectPublicKeyInfo),
		Fingerprint:	sha256hex(getRaw(entry)),
		NotBefore:	cert.NotBefore,
		NotAfter:	cert.NotAfter,
	}
}

func (info *certInfo) TypeString () string {
	if info.IsPrecert {
		return "precert"
	} else {
		return "cert"
	}
}

func (info *certInfo) TypeFriendlyString () string {
	if info.IsPrecert {
		return "Pre-certificate"
	} else {
		return "Certificate"
	}
}

func DumpLogEntry (out io.Writer, logUri string, entry *ct.LogEntry) {
	info := makeCertInfo(entry)

	fmt.Fprintf(out, "%d @ %s:\n", entry.Index, logUri)
	fmt.Fprintf(out, "\t         Type = %s\n", info.TypeFriendlyString())
	fmt.Fprintf(out, "\t    DNS Names = %v\n", info.DnsNames)
	fmt.Fprintf(out, "\t       Pubkey = %s\n", info.PubkeyHash)
	fmt.Fprintf(out, "\t  Fingerprint = %s\n", info.Fingerprint)
	fmt.Fprintf(out, "\t      Subject = %s\n", info.SubjectDn)
	fmt.Fprintf(out, "\t       Issuer = %s\n", info.IssuerDn)
	fmt.Fprintf(out, "\tRoot Operator = %s\n", info.RootOrg)
	fmt.Fprintf(out, "\t       Serial = %s\n", info.Serial)
	fmt.Fprintf(out, "\t   Not Before = %s\n", info.NotBefore)
	fmt.Fprintf(out, "\t    Not After = %s\n", info.NotAfter)
}

func InvokeHookScript (command string, logUri string, entry *ct.LogEntry) error {
	info := makeCertInfo(entry)

	cmd := exec.Command(command)
	cmd.Env = append(os.Environ(),
				"LOG_URI=" + logUri,
				"LOG_INDEX=" + strconv.FormatInt(entry.Index, 10),
				"CERT_TYPE=" + info.TypeString(),
				"SUBJECT_DN=" + info.SubjectDn,
				"ISSUER_DN=" + info.IssuerDn,
				"DNS_NAMES=" + strings.Join(info.DnsNames, ","),
				"SERIAL=" + info.Serial,
				"PUBKEY_HASH=" + info.PubkeyHash,
				"FINGERPRINT=" + info.Fingerprint,
				"NOT_BEFORE=" + strconv.FormatInt(info.NotBefore.Unix(), 10),
				"NOT_AFTER=" + strconv.FormatInt(info.NotAfter.Unix(), 10))
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

func WriteCertRepository (repoPath string, entry *ct.LogEntry) (bool, error) {
	fingerprint := sha256hex(getRaw(entry))
	prefixPath := filepath.Join(repoPath, fingerprint[0:2])
	var filenameSuffix string
	if entry.Precert != nil {
		filenameSuffix = ".precert.pem"
	} else if entry.X509Cert != nil {
		filenameSuffix = ".cert.pem"
	}
	if err := os.Mkdir(prefixPath, 0777); err != nil && !os.IsExist(err) {
		return false, fmt.Errorf("Failed to create prefix directory %s: %s", prefixPath, err)
	}
	path := filepath.Join(prefixPath, fingerprint + filenameSuffix)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return true, nil
		} else {
			return false, fmt.Errorf("Failed to open %s for writing: %s", path, err)
		}
	}
	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: getRaw(entry)}); err != nil {
		file.Close()
		return false, fmt.Errorf("Error writing to %s: %s", path, err)
	}
	for _, chainCert := range entry.Chain {
		if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: chainCert}); err != nil {
			file.Close()
			return false, fmt.Errorf("Error writing to %s: %s", path, err)
		}
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("Error writing to %s: %s", path, err)
	}

	return false, nil
}
