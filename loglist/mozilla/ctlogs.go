// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

// Package mozilla contains a parser for Mozilla's CTKnownLogs.h file
package mozilla

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// CTLogInfo describes a certificate transparency log from Mozilla's CTKnownLogs.h
// file.
type CTLogInfo struct {
	Name          string
	State         string // Admissible or Retired
	Timestamp     time.Time
	OperatorIndex int
	Key           []byte
}

// CTLogOperatorInfo describes a CT log operator from Mozilla's CTKnownLogs.h
// file.
type CTLogOperatorInfo struct {
	Name string
	ID   int
}

// Parse reads the CTKnownLogs.h content from r and returns the parsed logs and
// operators. Blocks enclosed by `#ifdef DEBUG` and `#endif` are ignored.
func Parse(r io.Reader) ([]CTLogInfo, []CTLogOperatorInfo, error) {
	scanner := bufio.NewScanner(r)
	skip := 0
	inLogs := false
	inOps := false

	var logs []CTLogInfo
	var ops []CTLogOperatorInfo

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, "#ifdef DEBUG"):
			skip++
			continue
		case strings.HasPrefix(trimmed, "#endif"):
			if skip > 0 {
				skip--
				continue
			}
		}

		if skip > 0 {
			continue
		}

		if strings.HasPrefix(trimmed, "const CTLogInfo kCTLogList[]") {
			inLogs = true
			continue
		}
		if strings.HasPrefix(trimmed, "const CTLogOperatorInfo kCTLogOperatorList[]") {
			inOps = true
			continue
		}

		if inLogs {
			if trimmed == "};" {
				inLogs = false
				continue
			}
			if strings.HasPrefix(trimmed, "{") {
				log, err := readLogEntry(trimmed, scanner)
				if err != nil {
					return nil, nil, err
				}
				logs = append(logs, log)
			}
			continue
		}

		if inOps {
			if trimmed == "};" {
				inOps = false
				continue
			}
			if strings.HasPrefix(trimmed, "{") {
				op, err := readOperatorEntry(trimmed)
				if err != nil {
					return nil, nil, err
				}
				ops = append(ops, op)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return logs, ops, nil
}

func readLogEntry(firstLine string, s *bufio.Scanner) (CTLogInfo, error) {
	var log CTLogInfo

	// Example first line:
	// {"Name", CTLogState::Admissible,
	firstLine = strings.TrimSpace(firstLine)
	if !strings.HasPrefix(firstLine, "{") {
		return log, errors.New("invalid log entry start")
	}
	firstLine = strings.TrimPrefix(firstLine, "{")
	firstLine = strings.TrimSuffix(firstLine, ",")

	parts := splitCSV(firstLine)
	var statePart string
	switch len(parts) {
	case 2:
		log.Name = trimQuotes(parts[0])
		statePart = parts[1]
	case 1:
		log.Name = trimQuotes(parts[0])
		if !s.Scan() {
			return log, io.ErrUnexpectedEOF
		}
		statePart = strings.TrimSpace(s.Text())
	default:
		return log, errors.New("invalid log entry header")
	}
	statePart = strings.TrimSuffix(strings.TrimSpace(statePart), ",")
	log.State = strings.TrimPrefix(statePart, "CTLogState::")

	// Next line: timestamp
	if !s.Scan() {
		return log, io.ErrUnexpectedEOF
	}
	tsLine := strings.TrimSpace(s.Text())
	tsValue := strings.Split(tsLine, ",")[0]
	ts, err := strconv.ParseInt(strings.TrimSpace(tsValue), 10, 64)
	if err != nil {
		return log, err
	}
	log.Timestamp = time.Unix(0, ts*int64(time.Millisecond))

	// Next line: operator index
	if !s.Scan() {
		return log, io.ErrUnexpectedEOF
	}
	opLine := strings.TrimSpace(s.Text())
	opValue := strings.Split(opLine, ",")[0]
	opIndex, err := strconv.Atoi(strings.TrimSpace(opValue))
	if err != nil {
		return log, err
	}
	log.OperatorIndex = opIndex

	// Key lines
	var keyHex strings.Builder
	for {
		if !s.Scan() {
			return log, io.ErrUnexpectedEOF
		}
		l := strings.TrimSpace(s.Text())
		if strings.HasPrefix(l, "\"") {
			// remove trailing comma if any
			trimmed := strings.TrimSuffix(l, ",")
			keyHex.WriteString(trimQuotes(trimmed))
			if strings.HasSuffix(l, ",") {
				// last key line
				break
			}
			continue
		}
		return log, errors.New("unexpected line while reading key")
	}

	key, err := decodeHexEscapes(keyHex.String())
	if err != nil {
		return log, err
	}

	// key length line
	if !s.Scan() {
		return log, io.ErrUnexpectedEOF
	}
	lenLine := strings.TrimSpace(s.Text())
	lenValue := strings.TrimSuffix(lenLine, "},")
	keyLen, err := strconv.Atoi(strings.TrimSpace(lenValue))
	if err != nil {
		return log, err
	}
	if len(key) != keyLen {
		// ignore mismatch but continue
	}
	log.Key = key
	return log, nil
}

func readOperatorEntry(line string) (CTLogOperatorInfo, error) {
	var op CTLogOperatorInfo
	line = strings.TrimSuffix(strings.TrimSpace(line), ",")
	if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
		return op, errors.New("invalid operator entry")
	}
	line = strings.TrimPrefix(line, "{")
	line = strings.TrimSuffix(line, "}")
	parts := splitCSV(line)
	if len(parts) != 2 {
		return op, errors.New("invalid operator fields")
	}
	op.Name = trimQuotes(parts[0])
	id, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return op, err
	}
	op.ID = id
	return op, nil
}

func splitCSV(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inQuote {
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		parts = append(parts, strings.TrimSpace(cur.String()))
	}
	return parts
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func decodeHexEscapes(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); {
		if i+3 >= len(s) || s[i] != '\\' || s[i+1] != 'x' {
			return nil, errors.New("invalid escape")
		}
		b, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(b))
		i += 4
	}
	return out, nil
}
