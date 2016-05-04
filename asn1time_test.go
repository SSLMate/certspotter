package certspotter

import (
	"testing"
	"time"
)

type timeTest struct {
	in	string
	ok	bool
	out	time.Time
}

var utcTimeTests = []timeTest{
	{ "9502101525Z", true, time.Date(1995, time.February, 10, 15, 25, 0, 0, time.UTC) },
	{ "950210152542Z", true, time.Date(1995, time.February, 10, 15, 25, 42, 0, time.UTC) },
	{ "1502101525Z", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.UTC) },
	{ "150210152542Z", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.UTC) },
	{ "1502101525+1000", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.FixedZone("", 10 * 3600)) },
	{ "1502101525-1000", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.FixedZone("", -1 * (10 * 3600))) },
	{ "1502101525+1035", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.FixedZone("", 10 * 3600 + 35 * 60)) },
	{ "1502101525-1035", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.FixedZone("", -1 * (10 * 3600 + 35 * 60))) },
	{ "150210152542+1000", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.FixedZone("", 10 * 3600)) },
	{ "150210152542-1000", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.FixedZone("", -1 * (10 * 3600))) },
	{ "150210152542+1035", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.FixedZone("", 10 * 3600 + 35 * 60)) },
	{ "150210152542-1035", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.FixedZone("", -1 * (10 * 3600 + 35 * 60))) },
	{ "1502101525", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.UTC) },
	{ "150210152542", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.UTC) },
	{ "", false, time.Time{} },
	{ "123", false, time.Time{} },
	{ "150210152542-10", false, time.Time{} },
	{ "150210152542F", false, time.Time{} },
	{ "150210152542ZF", false, time.Time{} },
}

func TestUTCTime(t *testing.T) {
	for i, test := range utcTimeTests {
		ret, err := parseUTCTime([]byte(test.in))
		if err != nil {
			if test.ok {
				t.Errorf("#%d: parseUTCTime(%q) failed with error %v", i, test.in, err)
			}
			continue
		}
		if !test.ok {
			t.Errorf("#%d: parseUTCTime(%q) succeeded, should have failed", i, test.in)
			continue
		}
		if !test.out.Equal(ret) {
			t.Errorf("#%d: parseUTCTime(%q) = %v, want %v", i, test.in, ret, test.out)
		}
	}
}

var generalizedTimeTests = []timeTest{
	{ "2015021015", true, time.Date(2015, time.February, 10, 15, 0, 0, 0, time.UTC) },
	{ "201502101525", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.UTC) },
	{ "20150210152542", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.UTC) },
	{ "20150210152542.123", true, time.Date(2015, time.February, 10, 15, 25, 42, 123000000, time.UTC) },
	{ "20150210152542.12", false, time.Time{} },
	{ "20150210152542.1", false, time.Time{} },
	{ "20150210152542.", false, time.Time{} },

	{ "2015021015Z", true, time.Date(2015, time.February, 10, 15, 0, 0, 0, time.UTC) },
	{ "201502101525Z", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.UTC) },
	{ "20150210152542Z", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.UTC) },
	{ "20150210152542.123Z", true, time.Date(2015, time.February, 10, 15, 25, 42, 123000000, time.UTC) },
	{ "20150210152542.12Z", false, time.Time{} },
	{ "20150210152542.1Z", false, time.Time{} },
	{ "20150210152542.Z", false, time.Time{} },

	{ "2015021015+1000", true, time.Date(2015, time.February, 10, 15, 0, 0, 0, time.FixedZone("", 10 * 3600)) },
	{ "201502101525+1000", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.FixedZone("", 10 * 3600)) },
	{ "20150210152542+1000", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.FixedZone("", 10 * 3600)) },
	{ "20150210152542.123+1000", true, time.Date(2015, time.February, 10, 15, 25, 42, 123000000, time.FixedZone("", 10 * 3600)) },
	{ "20150210152542.12+1000", false, time.Time{} },
	{ "20150210152542.1+1000", false, time.Time{} },
	{ "20150210152542.+1000", false, time.Time{} },

	{ "2015021015-0835", true, time.Date(2015, time.February, 10, 15, 0, 0, 0, time.FixedZone("", -1 * (8 * 3600 + 35 * 60))) },
	{ "201502101525-0835", true, time.Date(2015, time.February, 10, 15, 25, 0, 0, time.FixedZone("", -1 * (8 * 3600 + 35 * 60))) },
	{ "20150210152542-0835", true, time.Date(2015, time.February, 10, 15, 25, 42, 0, time.FixedZone("", -1 * (8 * 3600 + 35 * 60))) },
	{ "20150210152542.123-0835", true, time.Date(2015, time.February, 10, 15, 25, 42, 123000000, time.FixedZone("", -1 * (8 * 3600 + 35 * 60))) },
	{ "20150210152542.12-0835", false, time.Time{} },
	{ "20150210152542.1-0835", false, time.Time{} },
	{ "20150210152542.-0835", false, time.Time{} },


	{ "", false, time.Time{} },
	{ "123", false, time.Time{} },
	{ "2015021015+1000Z", false, time.Time{} },
	{ "2015021015x", false, time.Time{} },
	{ "201502101525Zf", false, time.Time{} },
}

func TestGeneralizedTime(t *testing.T) {
	for i, test := range generalizedTimeTests {
		ret, err := parseGeneralizedTime([]byte(test.in))
		if err != nil {
			if test.ok {
				t.Errorf("#%d: parseGeneralizedTime(%q) failed with error %v", i, test.in, err)
			}
			continue
		}
		if !test.ok {
			t.Errorf("#%d: parseGeneralizedTime(%q) succeeded, should have failed", i, test.in)
			continue
		}
		if !test.out.Equal(ret) {
			t.Errorf("#%d: parseGeneralizedTime(%q) = %v, want %v", i, test.in, ret, test.out)
		}
	}
}
