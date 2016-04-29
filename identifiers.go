package ctwatch

import (
	"bytes"
	"strings"
	"fmt"
	"net"
	"unicode/utf8"
	"golang.org/x/net/idna"
)

const invalidDNSLabelPlaceholder = "<invalid>"

/*
const (
	IdentifierSourceSubjectCN = iota
	IdentifierSourceDNSName
	IdentifierSourceIPAddr
)
type IdentifierSource int

type UnknownIdentifier struct {
	Source			IdentifierSource
	Value			[]byte
}
*/

type Identifiers struct {
	DNSNames		[]string	// stored as ASCII, with IDNs in Punycode
	IPAddrs			[]net.IP
	//Unknowns		[]UnknownIdentifier
}

func NewIdentifiers () *Identifiers {
	return &Identifiers{
		DNSNames:	[]string{},
		IPAddrs:	[]net.IP{},
		//Unknowns:	[]UnknownIdentifier{},
	}
}

func parseIPAddrString (str string) net.IP { // TODO
	return nil
}

func isASCIIString (value []byte) bool {
	for _, b := range value {
		if b > 127 {
			return false
		}
	}
	return true
}
func isUTF8String (value []byte) bool {
	return utf8.Valid(value)
}
func latin1ToUTF8 (value []byte) string {
	runes := make([]rune, len(value))
	for i, b := range value {
		runes[i] = rune(b)
	}
	return string(runes)
}

// Validate a DNS label.  We are less strict than we could be,
// because the main purpose of this is to prevent nasty characters
// from getting through that could cause headaches later (e.g. NUL,
// control characters).  In particular, we allow '_' (since it's
// quite common in hostnames despite being prohibited), '*' (since
// it's used to represent wildcards), and '?' (since it's used
// in CT to represent redacted labels).
func isValidDNSLabelChar (ch rune) bool {
	return (ch >= 'A' && ch <= 'Z') ||
	       (ch >= 'a' && ch <= 'z') ||
	       (ch >= '0' && ch <= '9') ||
	        ch == '-' || ch == '_' ||
		ch == '*' || ch == '?';
}
func isValidDNSLabel (label string) bool {
	for _, ch := range label {
		if !isValidDNSLabelChar(ch) {
			return false
		}
	}
	return true
}

// Convert the DNS name to lower case and replace invalid labels with a placeholder
func sanitizeDNSName (value string) string {
	value = strings.ToLower(value)
	labels := strings.Split(value, ".")
	for i, label := range labels {
		if !isValidDNSLabel(label) {
			labels[i] = invalidDNSLabelPlaceholder
		}
	}
	return strings.Join(labels, ".")
}

// Like sanitizeDNSName, but labels that are Unicode are converted to Punycode.
func sanitizeUnicodeDNSName (value string) string {
	value = strings.ToLower(value)
	labels := strings.Split(value, ".")
	for i, label := range labels {
		if asciiLabel, err := idna.ToASCII(label); err == nil && isValidDNSLabel(asciiLabel) {
			labels[i] = asciiLabel
		} else {
			labels[i] = invalidDNSLabelPlaceholder
		}
	}
	return strings.Join(labels, ".")
}

func (ids *Identifiers) addDnsSANnonull (value []byte) {
	if ipaddr := parseIPAddrString(string(value)); ipaddr != nil {
		// Stupid CAs put IP addresses in DNS SANs because stupid Microsoft
		// used to not support IP address SANs.  Since there's no way for an IP
		// address to also be a valid DNS name, just treat it like an IP address
		// and not try to process it as a DNS name.
		ids.IPAddrs = append(ids.IPAddrs, ipaddr)
	} else if isASCIIString(value) {
		ids.DNSNames = append(ids.DNSNames, sanitizeDNSName(string(value)))
	} else {
		// DNS SANs are supposed to be IA5Strings (i.e. ASCII) but CAs can't follow
		// simple rules.  Unfortunately, we have no idea what the encoding really is
		// in this case, so interpret it as both UTF-8 (if it's valid UTF-8)
		// and Latin-1.
		if isUTF8String(value) {
			ids.DNSNames = append(ids.DNSNames, sanitizeUnicodeDNSName(string(value)))
		}
		ids.DNSNames = append(ids.DNSNames, sanitizeUnicodeDNSName(latin1ToUTF8(value)))
	}
}

func (ids *Identifiers) AddDnsSAN (value []byte) {
	if nullIndex := bytes.IndexByte(value, 0); nullIndex != -1 {
		// If the value contains a null byte, process the part of
		// the value up to the first null byte in addition to the
		// complete value, in case this certificate is an attempt to
		// fake out validators that only compare up to the first null.
		ids.addDnsSANnonull(value[0:nullIndex])
	}
	ids.addDnsSANnonull(value)
}

func (ids *Identifiers) addCNnonull (value string) {
	if ipaddr := parseIPAddrString(value); ipaddr != nil {
		ids.IPAddrs = append(ids.IPAddrs, ipaddr)
	} else if !strings.ContainsRune(value, ' ') {
		// If the CN contains a space it's clearly not a DNS name, so ignore it.
		ids.DNSNames = append(ids.DNSNames, sanitizeUnicodeDNSName(value))
	}
}

func (ids *Identifiers) AddCN (value string) {
	if nullIndex := strings.IndexRune(value, 0); nullIndex != -1 {
		// If the value contains a null byte, process the part of
		// the value up to the first null byte in addition to the
		// complete value, in case this certificate is an attempt to
		// fake out validators that only compare up to the first null.
		ids.addCNnonull(value[0:nullIndex])
	}
	ids.addCNnonull(value)
}

func (ids *Identifiers) AddIPAddress (value net.IP) {
	ids.IPAddrs = append(ids.IPAddrs, value)
}

func (tbs *TBSCertificate) ParseIdentifiers () (*Identifiers, error) {
	ids := NewIdentifiers()

	cns, err := tbs.ParseSubjectCommonNames()
	if err != nil {
		return nil, err
	}
	for _, cn := range cns {
		ids.AddCN(cn)
	}

	sans, err := tbs.ParseSubjectAltNames()
	if err != nil {
		return nil, err
	}
	for _, san := range sans {
		switch san.Type {
		case sanDNSName:
			ids.AddDnsSAN(san.Value)
		case sanIPAddress:
			if !(len(san.Value) == 4 || len(san.Value) == 16) {
				return nil, fmt.Errorf("IP Address SAN has bogus length %d", len(san.Value))
			}
			ids.AddIPAddress(net.IP(san.Value))
		}
	}

	return ids, nil
}
