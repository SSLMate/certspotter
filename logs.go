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
)

type LogInfoFile struct {
	Logs []LogInfo `json:"logs"`
}
type LogInfo struct {
	Description string `json:"description"`
	Key         []byte `json:"key"`
	Url         string `json:"url"`
	MMD         int    `json:"maximum_merge_delay"`
}

func (info *LogInfo) FullURI() string {
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
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg=="),
		Url: "ct.ws.symantec.com",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB"),
		Url: "ctlog.api.venafi.com",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ=="),
		Url: "vega.ws.symantec.com",
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
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajWTOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ=="),
		Url: "ct.startssl.com",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQvAdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ=="),
		Url: "ctlog.wosign.com",
		MMD: 86400,
	},
	{
		Key: mustDecodeBase64("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArM8vS3Cs8Q2Wv+gK/kSd1IwXncOaEBGEE+2M+Tdtg+QAb7FLwKaJx2GPmjS7VlLKA1ZQ7yR/S0npNYHd8OcX9XLSI8XjE3/Xjng1j0nemASKY6+tojlwlYRoS5Ez/kzhMhfC8mG4Oo05f9WVgj5WGVBFb8sIMw3VGUIIGkhCEPFow8NBE8sNHtsCtyR6UZZuvAjqaa9t75KYjlXzZeXonL4aR2AwfXqArVaDepPDrpMraiiKpl9jGQy+fHshY0E4t/fodnNrhcy8civBUtBbXTFOnSrzTZtkFJkmxnH4e/hE1eMjIPMK14tRPnKA0nh4NS1K50CZEZU01C9/+V81NwIDAQAB"),
		Url: "www.certificatetransparency.cn/ct",
		MMD: 86400,
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
}

func mustDecodeBase64(str string) []byte {
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic("MustDecodeBase64: " + err.Error())
	}
	return bytes
}
