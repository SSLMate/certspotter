package main

import (
	"flag"
	"os"

	"src.agwa.name/ctwatch"
	"src.agwa.name/ctwatch/ct"
	"src.agwa.name/ctwatch/cmd"
)

func DefaultStateDir () string {
	if envVar := os.Getenv("CTPARSEWATCH_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("ctparsewatch")
	}
}

var stateDir = flag.String("state_dir", DefaultStateDir(), "Directory for storing state")

func processEntry (scanner *ctwatch.Scanner, entry *ct.LogEntry) {
	info := ctwatch.EntryInfo{
		LogUri:		scanner.LogUri,
		Entry:		entry,
		IsPrecert:	ctwatch.IsPrecert(entry),
		FullChain:	ctwatch.GetFullChain(entry),
	}

	info.CertInfo, info.ParseError = ctwatch.MakeCertInfoFromLogEntry(entry)
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
