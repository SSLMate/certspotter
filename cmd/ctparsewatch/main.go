package main

import (
	"flag"
	"os"

	"src.agwa.name/certspotter"
	"src.agwa.name/certspotter/ct"
	"src.agwa.name/certspotter/cmd"
)

func DefaultStateDir () string {
	if envVar := os.Getenv("CTPARSEWATCH_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("ctparsewatch")
	}
}

var stateDir = flag.String("state_dir", DefaultStateDir(), "Directory for storing state")

func processEntry (scanner *certspotter.Scanner, entry *ct.LogEntry) {
	info := certspotter.EntryInfo{
		LogUri:		scanner.LogUri,
		Entry:		entry,
		IsPrecert:	certspotter.IsPrecert(entry),
		FullChain:	certspotter.GetFullChain(entry),
	}

	info.CertInfo, info.ParseError = certspotter.MakeCertInfoFromLogEntry(entry)
	if info.CertInfo != nil {
		info.Identifiers, info.IdentifiersParseError = info.CertInfo.ParseIdentifiers()
	}

	if info.HasParseErrors() {
		cmd.LogEntry(&info)
	}
}

func main() {
	flag.Parse()
	cmd.Main(*stateDir, processEntry)
}
