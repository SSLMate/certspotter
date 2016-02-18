package ctwatch

import (
	"os"
	"fmt"
	"errors"
	"bytes"
	"encoding/binary"
	"encoding/asn1"
	"crypto/x509/pkix"
)

var (
	oidExtensionSubjectAltName	= []int{2, 5, 29, 17}
	oidCommonName			= []int{2, 5, 4, 3}
)

type rdnSequence []relativeDistinguishedNameSET
type relativeDistinguishedNameSET []attributeTypeAndValue
type attributeTypeAndValue struct {
	Type	asn1.ObjectIdentifier
	Value	asn1.RawValue
}

type tbsCertificate struct {
	Version			int		`asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber		asn1.RawValue
	SignatureAlgorithm	asn1.RawValue
	Issuer			asn1.RawValue
	Validity		asn1.RawValue
	Subject			asn1.RawValue
	PublicKey		asn1.RawValue
	UniqueId		asn1.BitString	`asn1:"optional,tag:1"`
	SubjectUniqueId		asn1.BitString	`asn1:"optional,tag:2"`
	Extensions		[]pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type certificate struct {
	TBSCertificate		asn1.RawValue
	SignatureAlgorithm	asn1.RawValue
	SignatureValue		asn1.RawValue
}

func stringFromByteSlice (chars []byte) string {
	runes := make([]rune, len(chars))
	for i, ch := range chars {
		runes[i] = rune(ch)
	}
	return string(runes)
}

func stringFromUint16Slice (chars []uint16) string {
	runes := make([]rune, len(chars))
	for i, ch := range chars {
		runes[i] = rune(ch)
	}
	return string(runes)
}

func stringFromUint32Slice (chars []uint32) string {
	runes := make([]rune, len(chars))
	for i, ch := range chars {
		runes[i] = rune(ch)
	}
	return string(runes)
}

func decodeString (value *asn1.RawValue) (string, error) {
	if !value.IsCompound && value.Class == 0 {
		if value.Tag == 12 {
			// UTF8String
			return string(value.Bytes), nil
		} else if value.Tag == 19 || value.Tag == 22 || value.Tag == 20 {
			// * PrintableString - subset of ASCII
			// * IA5String - ASCII
			// * TeletexString - 8 bit charset; not quite ISO-8859-1, but often treated as such

			// Don't enforce character set rules. Allow any 8 bit character, since
			// CAs routinely mess this up
			return stringFromByteSlice(value.Bytes), nil
		} else if value.Tag == 30 {
			// BMPString - Unicode, encoded in big-endian format using two octets
			runes := make([]uint16, len(value.Bytes) / 2)
			if err := binary.Read(bytes.NewReader(value.Bytes), binary.BigEndian, runes); err != nil {
				return "", errors.New("Malformed BMPString: " + err.Error())
			}
			return stringFromUint16Slice(runes), nil
		} else if value.Tag == 28 {
			// UniversalString - Unicode, encoded in big-endian format using four octets
			runes := make([]uint32, len(value.Bytes) / 4)
			if err := binary.Read(bytes.NewReader(value.Bytes), binary.BigEndian, runes); err != nil {
				return "", errors.New("Malformed UniversalString: " + err.Error())
			}
			return stringFromUint32Slice(runes), nil
		}
	}
	return "", errors.New("Not a string")
}

func getCNs (rdns *rdnSequence) ([]string, error) {
	var cns []string

	for _, rdn := range *rdns {
		if len(rdn) == 0 {
			continue
		}
		atv := rdn[0]
		if atv.Type.Equal(oidCommonName) {
			cnString, err := decodeString(&atv.Value)
			if err != nil {
				return nil, errors.New("Error decoding CN: " + err.Error())
			}
			cns = append(cns, cnString)
		}
	}

	return cns, nil
}

func parseSANExtension (value []byte) ([]string, error) {
	var dnsNames []string
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(value, &seq); err != nil {
		return nil, errors.New("failed to parse subjectAltName extension: " + err.Error())
	} else if len(rest) != 0 {
		fmt.Fprintf(os.Stderr, "Warning: trailing data after subjectAltName extension\n")
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
			dnsNames = append(dnsNames, string(val.Bytes))
		}
	}

	return dnsNames, nil
}

func ExtractDNSNamesFromTBS (tbsBytes []byte) ([]string, error) {
	var dnsNames []string

	var tbs tbsCertificate
	if rest, err := asn1.Unmarshal(tbsBytes, &tbs); err != nil {
		return nil, errors.New("failed to parse TBS: " + err.Error())
	} else if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: trailing data after TBS\n")
	}

	// Extract Common Name from Subject
	var subject rdnSequence
	if rest, err := asn1.Unmarshal(tbs.Subject.FullBytes, &subject); err != nil {
		return nil, errors.New("failed to parse certificate subject: " + err.Error())
	} else if len(rest) != 0 {
		fmt.Fprintf(os.Stderr, "Warning: trailing data after certificate subject\n")
	}
	cns, err := getCNs(&subject)
	if err != nil {
		return nil, errors.New("failed to process certificate subject: " + err.Error())
	}
	dnsNames = append(dnsNames, cns...)

	// Extract DNS names from SubjectAlternativeName extension
	for _, ext := range tbs.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			dnsSans, err := parseSANExtension(ext.Value)
			if err != nil {
				return nil, err
			}
			dnsNames = append(dnsNames, dnsSans...)
		}
	}

	return dnsNames, nil
}

func ExtractDNSNames (certBytes []byte) ([]string, error) {
	var cert certificate
	if rest, err := asn1.Unmarshal(certBytes, &cert); err != nil {
		return nil, errors.New("failed to parse certificate: " + err.Error())
	} else if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: trailing data after certificate\n")
	}

	return ExtractDNSNamesFromTBS(cert.TBSCertificate.FullBytes)
}
