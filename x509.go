package ctwatch

import (
	"fmt"
	"bytes"
	"errors"
	"encoding/asn1"
	"unicode/utf8"
	"math/big"
	"time"
)

var (
	oidExtensionSubjectAltName	= asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints	= asn1.ObjectIdentifier{2, 5, 29, 19}
	oidCountry		        = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization			= asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit		= asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName			= asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber			= asn1.ObjectIdentifier{2, 5, 4, 5}
	oidLocality			= asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince			= asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress		= asn1.ObjectIdentifier{2, 5, 4, 9}
	oidPostalCode			= asn1.ObjectIdentifier{2, 5, 4, 17}
)

type CertValidity struct {
	NotBefore	time.Time
	NotAfter	time.Time
}

type BasicConstraints struct {
	IsCA		bool	`asn1:"optional"`
	MaxPathLen	int	`asn1:"optional,default:-1"`
}

type Extension struct {
	Id		asn1.ObjectIdentifier
	Critical	bool `asn1:"optional"`
	Value		[]byte
}

type RDNSequence []RelativeDistinguishedNameSET
type RelativeDistinguishedNameSET []AttributeTypeAndValue
type AttributeTypeAndValue struct {
	Type	asn1.ObjectIdentifier
	Value	asn1.RawValue
}

type TBSCertificate struct {
	Raw			asn1.RawContent

	Version			int		`asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber		asn1.RawValue
	SignatureAlgorithm	asn1.RawValue
	Issuer			asn1.RawValue
	Validity		asn1.RawValue
	Subject			asn1.RawValue
	PublicKey		asn1.RawValue
	UniqueId		asn1.BitString	`asn1:"optional,tag:1"`
	SubjectUniqueId		asn1.BitString	`asn1:"optional,tag:2"`
	Extensions		[]Extension	`asn1:"optional,explicit,tag:3"`
}

type Certificate struct {
	Raw			asn1.RawContent

	TBSCertificate		asn1.RawValue
	SignatureAlgorithm	asn1.RawValue
	SignatureValue		asn1.RawValue
}


func (rdns RDNSequence) ParseCNs () ([]string, error) {
	var cns []string

	for _, rdn := range rdns {
		if len(rdn) == 0 {
			continue
		}
		atv := rdn[0]
		if atv.Type.Equal(oidCommonName) {
			cnString, err := decodeASN1String(&atv.Value)
			if err != nil {
				return nil, errors.New("Error decoding CN: " + err.Error())
			}
			cns = append(cns, cnString)
		}
	}

	return cns, nil
}

func rdnLabel (oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidCountry):		return "C"
	case oid.Equal(oidOrganization):	return "O"
	case oid.Equal(oidOrganizationalUnit):	return "OU"
	case oid.Equal(oidCommonName):		return "CN"
	case oid.Equal(oidSerialNumber):	return "serialNumber"
	case oid.Equal(oidLocality):		return "L"
	case oid.Equal(oidProvince):		return "ST"
	case oid.Equal(oidStreetAddress):	return "street"
	case oid.Equal(oidPostalCode):		return "postalCode"
	}
	return oid.String()
}

func (rdns RDNSequence) String () string {
	var buf bytes.Buffer

	for _, rdn := range rdns {
		if len(rdn) == 0 {
			continue
		}
		atv := rdn[0]

		if buf.Len() != 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(rdnLabel(atv.Type))
		buf.WriteString("=")
		valueString, err := decodeASN1String(&atv.Value)
		if err == nil {
			buf.WriteString(valueString)
		} else {
			fmt.Fprintf(&buf, "%v", atv.Value.FullBytes)
		}
	}

	return buf.String()
}

func ParseTBSCertificate (tbsBytes []byte) (*TBSCertificate, error) {
	var tbs TBSCertificate
	if rest, err := asn1.Unmarshal(tbsBytes, &tbs); err != nil {
		return nil, errors.New("failed to parse TBS: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after TBS: %v", rest)
	}
	return &tbs, nil
}

func (tbs *TBSCertificate) ParseValidity () (*CertValidity, error) {
	var rawValidity struct {
		NotBefore	asn1.RawValue
		NotAfter	asn1.RawValue
	}
	if rest, err := asn1.Unmarshal(tbs.Validity.FullBytes, &rawValidity); err != nil {
		return nil, errors.New("failed to parse validity: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after validity: %v", rest)
	}

	var validity CertValidity
	var err error
	if validity.NotBefore, err = decodeASN1Time(&rawValidity.NotBefore); err != nil {
		return nil, errors.New("failed to decode notBefore time: " + err.Error())
	}
	if validity.NotAfter, err = decodeASN1Time(&rawValidity.NotAfter); err != nil {
		return nil, errors.New("failed to decode notAfter time: " + err.Error())
	}

	return &validity, nil
}

func (tbs *TBSCertificate) ParseBasicConstraints () (*BasicConstraints, error) {
	constraintExts := tbs.GetExtension(oidExtensionBasicConstraints)
	if len(constraintExts) == 0 {
		return nil, nil
	} else if len(constraintExts) > 1 {
		return nil, fmt.Errorf("Certificate has more than one Basic Constraints extension")
	}

	var constraints BasicConstraints
	if rest, err := asn1.Unmarshal(constraintExts[0].Value, &constraints); err != nil {
		return nil, errors.New("failed to parse Basic Constraints: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after Basic Constraints: %v", rest)
	}
	return &constraints, nil
}

func (tbs *TBSCertificate) ParseSerialNumber () (*big.Int, error) {
	serialNumber := big.NewInt(0)
	if rest, err := asn1.Unmarshal(tbs.SerialNumber.FullBytes, &serialNumber); err != nil {
		return nil, errors.New("failed to parse serial number: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after serial number: %v", rest)
	}
	return serialNumber, nil
}

func (tbs *TBSCertificate) GetRawPublicKey () []byte {
	return tbs.PublicKey.FullBytes
}

func (tbs *TBSCertificate) GetRawSubject () []byte {
	return tbs.Subject.FullBytes
}

func (tbs *TBSCertificate) GetRawIssuer () []byte {
	return tbs.Issuer.FullBytes
}

func (tbs *TBSCertificate) ParseSubject () (RDNSequence, error) {
	var subject RDNSequence
	if rest, err := asn1.Unmarshal(tbs.GetRawSubject(), &subject); err != nil {
		return nil, errors.New("failed to parse certificate subject: " + err.Error())
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data in certificate subject: %v", rest)
	}
	return subject, nil
}

func (tbs *TBSCertificate) ParseIssuer () (RDNSequence, error) {
	var issuer RDNSequence
	if rest, err := asn1.Unmarshal(tbs.GetRawIssuer(), &issuer); err != nil {
		return nil, errors.New("failed to parse certificate issuer: " + err.Error())
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data in certificate issuer: %v", rest)
	}
	return issuer, nil
}

func (tbs *TBSCertificate) ParseCommonNames () ([]string, error) {
	subject, err := tbs.ParseSubject()
	if err != nil {
		return nil, err
	}
	cns, err := subject.ParseCNs()
	if err != nil {
		return nil, errors.New("failed to process certificate subject: " + err.Error())
	}

	return cns, nil
}

func (tbs *TBSCertificate) ParseDNSNames () ([]string, error) {
	dnsNames := []string{}

	// Extract DNS names from SubjectAlternativeName extension
	for _, sanExt := range tbs.GetExtension(oidExtensionSubjectAltName) {
		dnsSans, err := parseSANExtension(sanExt.Value)
		if err != nil {
			return nil, err
		}
		dnsNames = append(dnsNames, dnsSans...)
	}

	return dnsNames, nil
}

func (tbs *TBSCertificate) GetExtension (id asn1.ObjectIdentifier) []Extension {
	var exts []Extension
	for _, ext := range tbs.Extensions {
		if ext.Id.Equal(id) {
			exts = append(exts, ext)
		}
	}
	return exts
}


func ParseCertificate (certBytes []byte) (*Certificate, error) {
	var cert Certificate
	if rest, err := asn1.Unmarshal(certBytes, &cert); err != nil {
		return nil, errors.New("failed to parse certificate: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after certificate: %v", rest)
	}
	return &cert, nil
}

func (cert *Certificate) GetRawTBSCertificate () []byte {
	return cert.TBSCertificate.FullBytes
}

func (cert *Certificate) ParseTBSCertificate () (*TBSCertificate, error) {
	return ParseTBSCertificate(cert.GetRawTBSCertificate())
}

func parseSANExtension (value []byte) ([]string, error) {
	var dnsNames []string
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(value, &seq); err != nil {
		return nil, errors.New("failed to parse subjectAltName extension: " + err.Error())
	} else if len(rest) != 0 {
		// Don't complain if the SAN is followed by exactly one zero byte,
		// which is a common error.
		if !(len(rest) == 1 && rest[0] == 0) {
			return nil, fmt.Errorf("trailing data in subjectAltName extension: %v", rest)
		}
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return nil, errors.New("failed to parse subjectAltName extension: bad SAN sequence")
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var val asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &val)
		if err != nil {
			return nil, errors.New("failed to parse subjectAltName extension item: " + err.Error())
		}
		switch val.Tag {
		case 2:
			// This should be an IA5String (i.e. ASCII) with IDNs encoded in Punycode, but there are
			// too many certs in the wild which have UTF-8 in their DNS SANs.
			if !utf8.Valid(val.Bytes) {
				return nil, errors.New("failed to parse subjectAltName: DNS name contains invalid UTF-8")
			}
			dnsNames = append(dnsNames, string(val.Bytes))
		}
	}

	return dnsNames, nil
}

