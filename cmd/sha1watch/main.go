package main

import (
	"flag"
	"time"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/x509"

	"src.agwa.name/ctwatch/cmd"
)

var stateDir = flag.String("state_dir", cmd.DefaultStateDir("sha1watch"), "Directory for storing state")

type sha1Matcher struct { }

func (m sha1Matcher) CertificateMatches(c *x509.Certificate) bool {
	return c.NotBefore.After(time.Date(2016, time.January, 1, 0, 0, 0, 0, time.UTC)) &&
		(c.SignatureAlgorithm == x509.SHA1WithRSA ||
		 c.SignatureAlgorithm == x509.MD5WithRSA ||
		 c.SignatureAlgorithm == x509.MD2WithRSA ||
		 c.SignatureAlgorithm == x509.DSAWithSHA1 ||
		 c.SignatureAlgorithm == x509.ECDSAWithSHA1)
}

func (m sha1Matcher) PrecertificateMatches(pc *ct.Precertificate) bool {
	return m.CertificateMatches(&pc.TBSCertificate)
}

func main() {
	flag.Parse()

	cmd.Main(*stateDir, &sha1Matcher{})
}
