// Copyright (C) 2017 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ct"
	"software.sslmate.com/src/certspotter/ct/client"

	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var verbose = flag.Bool("v", false, "Enable verbose output")

type Certificate struct {
	Subject []byte
	Issuer  []byte
	Raw     []byte
}

func (cert *Certificate) Fingerprint() [32]byte {
	return sha256.Sum256(cert.Raw)
}

func (cert *Certificate) CommonName() string {
	subject, err := certspotter.ParseRDNSequence(cert.Subject)
	if err != nil {
		return "???"
	}
	cns, err := subject.ParseCNs()
	if err != nil || len(cns) == 0 {
		return "???"
	}
	return cns[0]
}

func parseCertificate(data []byte) (*Certificate, error) {
	crt, err := certspotter.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	tbs, err := crt.ParseTBSCertificate()
	if err != nil {
		return nil, err
	}

	return &Certificate{
		Subject: tbs.Subject.FullBytes,
		Issuer:  tbs.Issuer.FullBytes,
		Raw:     data,
	}, nil
}

type Chain []*Certificate

func (c Chain) GetRawCerts() [][]byte {
	rawCerts := make([][]byte, len(c))
	for i := range c {
		rawCerts[i] = c[i].Raw
	}
	return rawCerts
}

type CertificateBunch struct {
	byFingerprint map[[32]byte]*Certificate
	bySubject     map[[32]byte]*Certificate
}

func MakeCertificateBunch() CertificateBunch {
	return CertificateBunch{
		byFingerprint: make(map[[32]byte]*Certificate),
		bySubject:     make(map[[32]byte]*Certificate),
	}
}

func (certs *CertificateBunch) Add(cert *Certificate) {
	certs.byFingerprint[cert.Fingerprint()] = cert
	certs.bySubject[sha256.Sum256(cert.Subject)] = cert
}

func (certs *CertificateBunch) FindBySubject(subject []byte) *Certificate {
	return certs.bySubject[sha256.Sum256(subject)]
}

type Log struct {
	info   certspotter.LogInfo
	verify *ct.SignatureVerifier
	client *client.LogClient
}

func (ctlog *Log) SubmitChain(chain Chain) (*ct.SignedCertificateTimestamp, error) {
	rawCerts := chain.GetRawCerts()
	sct, err := ctlog.client.AddChain(rawCerts)
	if err != nil {
		return nil, err
	}

	if err := certspotter.VerifyX509SCT(sct, rawCerts[0], ctlog.verify); err != nil {
		return nil, fmt.Errorf("Bad SCT signature: %s", err)
	}
	return sct, nil
}

func buildChain(cert *Certificate, certs *CertificateBunch) Chain {
	chain := make([]*Certificate, 0)
	for len(chain) < 16 && cert != nil && !bytes.Equal(cert.Subject, cert.Issuer) {
		chain = append(chain, cert)
		cert = certs.FindBySubject(cert.Issuer)
	}
	return chain
}

func main() {
	flag.Parse()
	log.SetPrefix("submitct: ")

	certsPem, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Error reading stdin: %s", err)
	}

	logs := make([]Log, 0, len(certspotter.OpenLogs))
	for _, loginfo := range certspotter.OpenLogs {
		pubkey, err := loginfo.ParsedPublicKey()
		if err != nil {
			log.Fatalf("%s: Failed to parse log public key: %s", loginfo.Url, err)
		}
		verify, err := ct.NewSignatureVerifier(pubkey)
		if err != nil {
			log.Fatalf("%s: Failed to create signature verifier for log: %s", loginfo.Url, err)
		}
		logs = append(logs, Log{
			info:   loginfo,
			verify: verify,
			client: client.New(loginfo.FullURI()),
		})
	}

	certs := MakeCertificateBunch()
	var parseErrors uint32
	var submitErrors uint32

	for len(certsPem) > 0 {
		var pemBlock *pem.Block
		pemBlock, certsPem = pem.Decode(certsPem)
		if pemBlock == nil {
			log.Fatalf("Invalid PEM read from stdin")
		}
		if pemBlock.Type != "CERTIFICATE" {
			log.Printf("Ignoring non-certificate read from stdin")
			continue
		}

		cert, err := parseCertificate(pemBlock.Bytes)
		if err != nil {
			log.Printf("Ignoring un-parseable certificate read from stdin: %s", err)
			parseErrors++
			continue
		}
		certs.Add(cert)
	}

	wg := sync.WaitGroup{}
	for fingerprint, cert := range certs.byFingerprint {
		cn := cert.CommonName()
		chain := buildChain(cert, &certs)
		if len(chain) == 0 {
			continue
		}
		for _, ctlog := range logs {
			wg.Add(1)
			go func(fingerprint [32]byte, ctlog Log) {
				sct, err := ctlog.SubmitChain(chain)
				if err != nil {
					log.Printf("%x (%s): %s: Submission Error: %s", fingerprint, cn, ctlog.info.Url, err)
					atomic.AddUint32(&submitErrors, 1)
				} else if *verbose {
					timestamp := time.Unix(int64(sct.Timestamp)/1000, int64(sct.Timestamp%1000)*1000000)
					log.Printf("%x (%s): %s: Submitted at %s", fingerprint, cn, ctlog.info.Url, timestamp)
				}
				wg.Done()
			}(fingerprint, ctlog)
		}
	}
	wg.Wait()

	exitStatus := 0
	if parseErrors > 0 {
		log.Printf("%d certificates failed to parse and were ignored", parseErrors)
		exitStatus |= 4
	}
	if submitErrors > 0 {
		log.Printf("%d submission errors occurred", submitErrors)
		exitStatus |= 8
	}
	os.Exit(exitStatus)
}
