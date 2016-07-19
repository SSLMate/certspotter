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
	"encoding/base64"
	"crypto"
	"crypto/x509"
)

type LogInfoFile struct {
	Logs		[]LogInfo	`json:"logs"`
}
type LogInfo struct {
	Description	string		`json:"description"`
	Key		[]byte		`json:"key"`
	Url		string		`json:"url"`
	MMD		int		`json:"maximum_merge_delay"`
}

func (info *LogInfo) FullURI () string {
	return "https://" + info.Url
}

func (info *LogInfo) ParsedPublicKey () (crypto.PublicKey, error) {
	if info.Key != nil {
		return x509.ParsePKIXPublicKey(info.Key)
	} else {
		return nil, nil
	}
}

var DefaultLogs = []LogInfo{
	{
		// a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10
		Description: "Google 'Pilot' log",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA=="),
		Url: "ct.googleapis.com/pilot",
		MMD: 86400,
	},
	{
		// 68f698f81f6482be3a8ceeb9281d4cfc71515d6793d444d10a67acbb4f4ffbc4
		Description: "Google 'Aviator' log",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q=="),
		Url: "ct.googleapis.com/aviator",
		MMD: 86400,
	},
	{
		// 5614069a2fd7c2ecd3f5e1bd44b23ec74676b9bc99115cc0ef949855d689d0dd
		Description: "DigiCert Log Server",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A=="),
		Url: "ct1.digicert-ct.com/log",
		MMD: 86400,
	},
	{
		// ee4bbdb775ce60bae142691fabe19e66a30f7e5fb072d88300c47b897aa8fdcb
		Description: "Google 'Rocketeer' log",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg=="),
		Url: "ct.googleapis.com/rocketeer",
		MMD: 86400,
	},
	{
		// 7461b4a09cfb3d41d75159575b2e7649a445a8d27709b0cc564a6482b7eb41a3
		Description: "Izenpe log",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg=="),
		Url: "ct.izenpe.com",
		MMD: 86400,
	},
	{
		// ddeb1d2b7a0d4fa6208b81ad8168707e2e8e9d01d55c888d3d11c4cdb6ecbecc
		Description: "Symantec log",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg=="),
		Url: "ct.ws.symantec.com",
		MMD: 86400,
	},
	{
		// ac3b9aed7fa9674757159e6d7d575672f9d98100941e9bdeffeca1313b75782d
		Description: "Venafi log",
		Key: mustDecodeBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB"),
		Url: "ctlog.api.venafi.com",
		MMD: 86400,
	},
	{
		// bc78e1dfc5f63c684649334da10fa15f0979692009c081b4f3f6917f3ed9b8a5
		Description: "Symantec 'Vega' log",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ=="),
		Url: "vega.ws.symantec.com",
		MMD: 86400,
	},
}

// Logs which monitor certs from distrusted roots
var UnderwaterLogs = []LogInfo{
	{
		Description: "Google 'Submariner' log",
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOfifIGLUV1Voou9JLfA5LZreRLSUMOCeeic8q3Dw0fpRkGMWV0Gtq20fgHQweQJeLVmEByQj9p81uIW4QkWkTw=="),
		Url: "ct.googleapis.com/submariner",
		MMD: 86400,
	},
}

func mustDecodeBase64 (str string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic("MustDecodeBase64: " + err.Error())
	}
	return bytes
}
