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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"time"
)

var http_flag = flag.Bool("http", false, "Connect to CT logs over http instead of https, useful for testing")

type LogInfoFile struct {
	Logs []LogInfo `json:"logs"`
}
type LogInfo struct {
	Description     string     `json:"description"`
	Key             []byte     `json:"key"`
	Url             string     `json:"url"`
	MMD             int        `json:"maximum_merge_delay"`
	CertExpiryBegin *time.Time `json:"cert_expiry_begin"`
	CertExpiryEnd   *time.Time `json:"cert_expiry_end"`
}

func (info *LogInfo) FullURI() string {
	if *http_flag {
		return "http://" + info.Url
	}
	return "https://" + info.Url
}

func (info *LogInfo) ParsedPublicKey() (crypto.PublicKey, error) {
	if info.Key != nil {
		return x509.ParsePKIXPublicKey(info.Key)
	} else {
		return nil, nil
	}
}

func (info *LogInfo) ID() []byte {
	sum := sha256.Sum256(info.Key)
	return sum[:]
}

var DefaultLogs = []LogInfo{
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA=="),
		Url: "ct.googleapis.com/pilot",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q=="),
		Url: "ct.googleapis.com/aviator",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A=="),
		Url: "ct1.digicert-ct.com/log",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg=="),
		Url: "ct.googleapis.com/rocketeer",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXhhuAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhsHq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLaypvurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYtNQIDAQAB"),
		Url: "ctserver.cnnic.cn",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA=="),
		Url: "ct.googleapis.com/icarus",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA=="),
		Url: "ct.googleapis.com/skydiver",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjicnerZVCXTrbEuUhGW85BXx6lrYfA43zro/bAna5ymW00VQb94etBzSg4j/KS/Oqf/fNN51D8DMGA2ULvw3AQ=="),
		Url: "ctlog-gen2.api.venafi.com",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw=="),
		Url: "mammoth.ct.comodo.com",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA=="),
		Url: "sabre.ct.comodo.com",
		MMD: 86400,
	},
	{
		Key:             mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI3MQm+HzXvaYa2mVlhB4zknbtAT8cSxakmBoJcBKGqGwYS0bhxSpuvABM1kdBTDpQhXnVdcq+LSiukXJRpGHVg=="),
		Url:             "ct.googleapis.com/logs/argon2019",
		MMD:             86400,
		CertExpiryBegin: makeTime(1546300800),
		CertExpiryEnd:   makeTime(1577836800),
	},
	{
		Key:             mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA=="),
		Url:             "ct.googleapis.com/logs/argon2020",
		MMD:             86400,
		CertExpiryBegin: makeTime(1577836800),
		CertExpiryEnd:   makeTime(1609459200),
	},
	{
		Key:             mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw=="),
		Url:             "ct.googleapis.com/logs/argon2021",
		MMD:             86400,
		CertExpiryBegin: makeTime(1609459200),
		CertExpiryEnd:   makeTime(1640995200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA=="),
		Url: "ct2.digicert-ct.com/log",
		MMD: 86400,
	},
	{
		Key:             mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZHz1v5r8a9LmXSMegYZAg4UW+Ug56GtNfJTDNFZuubEJYgWf4FcC5D+ZkYwttXTDSo4OkanG9b3AI4swIQ28g=="),
		Url:             "ct.cloudflare.com/logs/nimbus2019",
		MMD:             86400,
		CertExpiryBegin: makeTime(1546300800),
		CertExpiryEnd:   makeTime(1577836800),
	},
	{
		Key:             mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE01EAhx4o0zPQrXTcYjgCt4MVFsT0Pwjzb1RwrM0lhWDlxAYPP6/gyMCXNkOn/7KFsjL7rwk78tHMpY8rXn8AYg=="),
		Url:             "ct.cloudflare.com/logs/nimbus2020",
		MMD:             86400,
		CertExpiryBegin: makeTime(1577836800),
		CertExpiryEnd:   makeTime(1609459200),
	},
	{
		Key:             mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExpon7ipsqehIeU1bmpog9TFo4Pk8+9oN8OYHl1Q2JGVXnkVFnuuvPgSo2Ep+6vLffNLcmEbxOucz03sFiematg=="),
		Url:             "ct.cloudflare.com/logs/nimbus2021",
		MMD:             86400,
		CertExpiryBegin: makeTime(1609459200),
		CertExpiryEnd:   makeTime(1640995200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESLJHTlAycmJKDQxIv60pZG8g33lSYxYpCi5gteI6HLevWbFVCdtZx+m9b+0LrwWWl/87mkNN6xE0M4rnrIPA/w=="),
		Url: "ct.cloudflare.com/logs/nimbus2022",
		MMD: 86400,
		CertExpiryBegin: makeTime(1640995200),
		CertExpiryEnd: makeTime(1672531200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/8tkhjLRp0SXrlZdTzNkTd6HqmcmXiDJz3fAdWLgOhjmv4mohvRhwXul9bgW0ODgRwC9UGAgH/vpGHPvIS1qA=="),
		Url: "ct.cloudflare.com/logs/nimbus2023",
		MMD: 86400,
		CertExpiryBegin: makeTime(1672531200),
		CertExpiryEnd: makeTime(1704067200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZd/ow8X+FSVWAVSf8xzkFohcPph/x6pS1JHh7g1wnCZ5y/8Hk6jzJxs6t3YMAWz2CPd4VkCdxwKexGhcFxD9A=="),
		Url: "yeti2019.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1546300800),
		CertExpiryEnd: makeTime(1577836800),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEURAG+Zo0ac3n37ifZKUhBFEV6jfcCzGIRz3tsq8Ca9BP/5XUHy6ZiqsPaAEbVM0uI3Tm9U24RVBHR9JxDElPmg=="),
		Url: "yeti2020.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1577836800),
		CertExpiryEnd: makeTime(1609459200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6J4EbcpIAl1+AkSRsbhoY5oRTj3VoFfaf1DlQkfi7Rbe/HcjfVtrwN8jaC+tQDGjF+dqvKhWJAQ6Q6ev6q9Mew=="),
		Url: "yeti2021.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1609459200),
		CertExpiryEnd: makeTime(1640995200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn/jYHd77W1G1+131td5mEbCdX/1v/KiYW5hPLcOROvv+xA8Nw2BDjB7y+RGyutD2vKXStp/5XIeiffzUfdYTJg=="),
		Url: "yeti2022.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1640995200),
		CertExpiryEnd: makeTime(1672531200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4hHIyMVIrR9oShgbQMYEk8WX1lmkfFKB448Gn93KbsZnnwljDHY6MQqEnWfKGgMOq0gh3QK48c5ZB3UKSIFZ4g=="),
		Url: "nessie2020.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1577836800),
		CertExpiryEnd: makeTime(1609459200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9o7AiwrbGBIX6Lnc47I6OfLMdZnRzKoP5u072nBi6vpIOEooktTi1gNwlRPzGC2ySGfuc1xLDeaA/wSFGgpYFg=="),
		Url: "nessie2021.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1609459200),
		CertExpiryEnd: makeTime(1640995200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJyTdaAMoy/5jvg4RR019F2ihEV1McclBKMe2okuX7MCv/C87v+nxsfz1Af+p+0lADGMkmNd5LqZVqxbGvlHYcQ=="),
		Url: "nessie2022.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1640995200),
		CertExpiryEnd: makeTime(1672531200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEXu8iQwSCRSf2CbITGpUpBtFVt8+I0IU0d1C36Lfe1+fbwdaI0Z5FktfM2fBoI1bXBd18k2ggKGYGgdZBgLKTg=="),
		Url: "nessie2023.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1672531200),
		CertExpiryEnd: makeTime(1704067200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfQ0DsdWYitzwFTvG3F4Nbj8Nv5XIVYzQpkyWsU4nuSYlmcwrAp6m092fsdXEw6w1BAeHlzaqrSgNfyvZaJ9y0Q=="),
		Url: "yeti2023.ct.digicert.com/log",
		MMD: 86400,
		CertExpiryBegin: makeTime(1672531200),
		CertExpiryEnd: makeTime(1704067200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeIPc6fGmuBg6AJkv/z7NFckmHvf/OqmjchZJ6wm2qN200keRDg352dWpi7CHnSV51BpQYAj1CQY5JuRAwrrDwg=="),
		Url: "ct.googleapis.com/logs/argon2022",
		MMD: 86400,
		CertExpiryBegin: makeTime(1640995200),
		CertExpiryEnd: makeTime(1672531200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA=="),
		Url: "ct.googleapis.com/logs/argon2023",
		MMD: 86400,
		CertExpiryBegin: makeTime(1672531200),
		CertExpiryEnd: makeTime(1704067200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEchY+C+/vzj5g3ZXLY3q5qY1Kb2zcYYCmRV4vg6yU84WI0KV00HuO/8XuQqLwLZPjwtCymeLhQunSxgAnaXSuzg=="),
		Url: "ct.googleapis.com/logs/xenon2023",
		MMD: 86400,
		CertExpiryBegin: makeTime(1672531200),
		CertExpiryEnd: makeTime(1704067200),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfzb42Zdr/h7hgqgDCo1vrNJqGqbcUvJGJEER9DDqp19W/wFSB0l166hD+U5cAXchpH8ZkBNUuvOHS0OnJ4oJrQ=="),
		Url: "oak.ct.letsencrypt.org/2020",
		MMD: 86400,
		CertExpiryBegin: makeTime(1577836800),
		CertExpiryEnd: makeTime(1609977600),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELsYzGMNwo8rBIlaklBIdmD2Ofn6HkfrjK0Ukz1uOIUC6Lm0jTITCXhoIdjs7JkyXnwuwYiJYiH7sE1YeKu8k9w=="),
		Url: "oak.ct.letsencrypt.org/2021",
		MMD: 86400,
		CertExpiryBegin: makeTime(1609459200),
		CertExpiryEnd: makeTime(1641513600),
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhjyxDVIjWt5u9sB/o2S8rcGJ2pdZTGA8+IpXhI/tvKBjElGE5r3de4yAfeOPhqTqqc+o7vPgXnDgu/a9/B+RLg=="),
		Url: "oak.ct.letsencrypt.org/2022",
		MMD: 86400,
		CertExpiryBegin: makeTime(1640995200),
		CertExpiryEnd: makeTime(1673049600),
	},
}

// Logs which monitor certs from distrusted roots
var UnderwaterLogs = []LogInfo{
	{
		Description: "Google 'Submariner' log",
		Key:         mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOfifIGLUV1Voou9JLfA5LZreRLSUMOCeeic8q3Dw0fpRkGMWV0Gtq20fgHQweQJeLVmEByQj9p81uIW4QkWkTw=="),
		Url:         "ct.googleapis.com/submariner",
		MMD:         86400,
	},
}

// Logs which accept submissions from anyone
var OpenLogs = []LogInfo{
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA=="),
		Url: "ct.googleapis.com/pilot",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg=="),
		Url: "ct.googleapis.com/rocketeer",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPXCMfVjQ2oWSgrewu4fIW4Sfh3lco90CwKZ061pvAI1eflh6c8ACE90pKM0muBDHCN+j0HV7scco4KKQPqq4A=="),
		Url: "dodo.ct.comodo.com",
		MMD: 86400,
	},
}

func mustDecodeBase64(str string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic("MustDecodeBase64: " + err.Error())
	}
	return bytes
}
func makeTime(seconds int64) *time.Time {
	t := time.Unix(seconds, 0)
	return &t
}
