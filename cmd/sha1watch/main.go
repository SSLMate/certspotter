package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/x509"

	"src.agwa.name/ctwatch/cmd"
)

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
	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] log_uri state_file\n", os.Args[0])
		os.Exit(2)
	}

	logUri := flag.Arg(0)
	stateFile := flag.Arg(1)

	cmd.Main(logUri, stateFile, &sha1Matcher{})
}
