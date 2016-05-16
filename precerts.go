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
	"fmt"
	"errors"
	"bytes"
	"encoding/asn1"
)

func bitStringEqual (a, b *asn1.BitString) bool {
	return a.BitLength == b.BitLength && bytes.Equal(a.Bytes, b.Bytes)
}

var (
	oidExtensionAuthorityKeyId	= []int{2, 5, 29, 35}
	oidExtensionSCT			= []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidExtensionCTPoison		= []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
)
func ValidatePrecert (precertBytes []byte, tbsBytes []byte) error {
	precert, err := ParseCertificate(precertBytes)
	if err != nil {
		return errors.New("failed to parse pre-certificate: " + err.Error())
	}
	precertTBS, err := precert.ParseTBSCertificate()
	if err != nil {
		return errors.New("failed to parse pre-certificate TBS: " + err.Error())
	}
	tbs, err := ParseTBSCertificate(tbsBytes)
	if err != nil {
		return errors.New("failed to parse TBS: " + err.Error())
	}

	// Everything must be equal except:
	//  issuer
	//  Authority Key Identifier extension (both must have it OR neither can have it)
	//  CT poison extension (precert must have it, TBS must not have it)
	if precertTBS.Version != tbs.Version {
		return errors.New("version not equal")
	}
	if !bytes.Equal(precertTBS.SerialNumber.FullBytes, tbs.SerialNumber.FullBytes) {
		return errors.New("serial number not equal")
	}
	sameIssuer := bytes.Equal(precertTBS.Issuer.FullBytes, tbs.Issuer.FullBytes)
	if !bytes.Equal(precertTBS.SignatureAlgorithm.FullBytes, tbs.SignatureAlgorithm.FullBytes) {
		return errors.New("SignatureAlgorithm not equal")
	}
	if !bytes.Equal(precertTBS.Validity.FullBytes, tbs.Validity.FullBytes) {
		return errors.New("Validity not equal")
	}
	if !bytes.Equal(precertTBS.Subject.FullBytes, tbs.Subject.FullBytes) {
		return errors.New("Subject not equal")
	}
	if !bytes.Equal(precertTBS.PublicKey.FullBytes, tbs.PublicKey.FullBytes) {
		return errors.New("PublicKey not equal")
	}
	if !bitStringEqual(&precertTBS.UniqueId, &tbs.UniqueId) {
		return errors.New("UniqueId not equal")
	}
	if !bitStringEqual(&precertTBS.SubjectUniqueId, &tbs.SubjectUniqueId) {
		return errors.New("SubjectUniqueId not equal")
	}

	precertHasPoison := false
	tbsIndex := 0
	for precertIndex := range precertTBS.Extensions {
		precertExt := &precertTBS.Extensions[precertIndex]

		if precertExt.Id.Equal(oidExtensionCTPoison) {
			if !precertExt.Critical {
				return errors.New("pre-cert poison extension is not critical")
			}
			/* CAs can't even get this right, and Google's logs don't check.  Fortunately,
			   it's not that important.
			if !bytes.Equal(precertExt.Value, []byte{0x05, 0x00}) {
				return errors.New("pre-cert poison extension contains incorrect value")
			}
			*/
			precertHasPoison = true
			continue
		}

		if tbsIndex >= len(tbs.Extensions) {
			return errors.New("pre-cert contains extension not in TBS")
		}
		tbsExt := &tbs.Extensions[tbsIndex]

		if !precertExt.Id.Equal(tbsExt.Id) {
			return fmt.Errorf("pre-cert and TBS contain different extensions (%v vs %v)", precertExt.Id, tbsExt.Id)
		}
		if precertExt.Critical != tbsExt.Critical {
			return fmt.Errorf("pre-cert and TBS %v extension differs in criticality", precertExt.Id)
		}
		if !precertExt.Id.Equal(oidExtensionAuthorityKeyId) || sameIssuer {
			if !bytes.Equal(precertExt.Value, tbsExt.Value) {
				return fmt.Errorf("pre-cert and TBS %v extension differs in value", precertExt.Id)
			}
		}

		tbsIndex++
	}
	if tbsIndex < len(tbs.Extensions) {
		return errors.New("TBS contains extension not in pre-cert")
	}
	if !precertHasPoison {
		return errors.New("pre-cert does not have poison extension")
	}

	return nil
}
func ReconstructPrecertTBS (tbs *TBSCertificate) (*TBSCertificate, error) {
	precertTBS := TBSCertificate{
		Version:		tbs.Version,
		SerialNumber:		tbs.SerialNumber,
		SignatureAlgorithm:	tbs.SignatureAlgorithm,
		Issuer:			tbs.Issuer,
		Validity:		tbs.Validity,
		Subject:		tbs.Subject,
		PublicKey:		tbs.PublicKey,
		UniqueId:		tbs.UniqueId,
		SubjectUniqueId:	tbs.SubjectUniqueId,
		Extensions:		make([]Extension, 0, len(tbs.Extensions)),
	}

	for _, ext := range tbs.Extensions {
		if !ext.Id.Equal(oidExtensionSCT) {
			precertTBS.Extensions = append(precertTBS.Extensions, ext)
		}
	}

	var err error
	precertTBS.Raw, err = asn1.Marshal(precertTBS)
	return &precertTBS, err
}
