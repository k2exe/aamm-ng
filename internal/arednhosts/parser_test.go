package arednhosts

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePreservesSectionsAndEntryOrder(t *testing.T) {
	records := []string{
		`##192.0.2.10##
192.0.2.10 TEST-NODE-A
198.51.100.10 test-device-a
192.0.2.10 supernode.TEST-NODE-A.local.mesh

##192.0.2.20##
192.0.2.20 TEST-NODE-B
198.51.100.20 lan.TEST-NODE-B.local.mesh
`,
		`ignored before section
##203.0.113.30##
203.0.113.30 TEST-NODE-C
malformed
203.0.113.31 dtdlink.TEST-NODE-C.local.mesh
`,
	}

	got := Parse(records)

	want := []Section{
		{
			Originator: netip.MustParseAddr("192.0.2.10"),
			Entries: []Entry{
				{
					Address: netip.MustParseAddr("192.0.2.10"),
					Name:    "TEST-NODE-A",
				},
				{
					Address: netip.MustParseAddr("198.51.100.10"),
					Name:    "test-device-a",
				},
				{
					Address: netip.MustParseAddr("192.0.2.10"),
					Name:    "supernode.TEST-NODE-A.local.mesh",
				},
			},
		},
		{
			Originator: netip.MustParseAddr("192.0.2.20"),
			Entries: []Entry{
				{
					Address: netip.MustParseAddr("192.0.2.20"),
					Name:    "TEST-NODE-B",
				},
				{
					Address: netip.MustParseAddr("198.51.100.20"),
					Name:    "lan.TEST-NODE-B.local.mesh",
				},
			},
		},
		{
			Originator: netip.MustParseAddr("203.0.113.30"),
			Entries: []Entry{
				{
					Address: netip.MustParseAddr("203.0.113.30"),
					Name:    "TEST-NODE-C",
				},
				{
					Address: netip.MustParseAddr("203.0.113.31"),
					Name:    "dtdlink.TEST-NODE-C.local.mesh",
				},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"sections = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestParseInvalidHeaderStopsPreviousSection(t *testing.T) {
	records := []string{
		`##192.0.2.10##
192.0.2.10 TEST-NODE-A

##not-an-address##
198.51.100.10 MUST-NOT-LEAK

##192.0.2.20##
192.0.2.20 TEST-NODE-B
`,
	}

	got := Parse(records)

	want := []Section{
		{
			Originator: netip.MustParseAddr("192.0.2.10"),
			Entries: []Entry{
				{
					Address: netip.MustParseAddr("192.0.2.10"),
					Name:    "TEST-NODE-A",
				},
			},
		},
		{
			Originator: netip.MustParseAddr("192.0.2.20"),
			Entries: []Entry{
				{
					Address: netip.MustParseAddr("192.0.2.20"),
					Name:    "TEST-NODE-B",
				},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"sections = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestParseIgnoresIPv6SectionsAndEntries(t *testing.T) {
	records := []string{
		`##2001:db8::10##
2001:db8::10 TEST-NODE-V6

##192.0.2.30##
2001:db8::20 TEST-DEVICE-V6
192.0.2.30 TEST-NODE-V4
`,
	}

	got := Parse(records)

	want := []Section{
		{
			Originator: netip.MustParseAddr("192.0.2.30"),
			Entries: []Entry{
				{
					Address: netip.MustParseAddr("192.0.2.30"),
					Name:    "TEST-NODE-V4",
				},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"sections = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestParseIgnoresMalformedEntries(t *testing.T) {
	records := []string{
		`## 192.0.2.40 ##
not-an-address TEST-BAD-ADDRESS
192.0.2.41
192.0.2.42 TEST-DEVICE-WITH-ALIASES alias-one alias-two
192.0.2.43 TEST-DEVICE
`,
	}

	got := Parse(records)

	want := []Section{
		{
			Originator: netip.MustParseAddr("192.0.2.40"),
			Entries: []Entry{
				{
					Address: netip.MustParseAddr("192.0.2.42"),
					Name:    "TEST-DEVICE-WITH-ALIASES",
				},
				{
					Address: netip.MustParseAddr("192.0.2.43"),
					Name:    "TEST-DEVICE",
				},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"sections = %#v; want %#v",
			got,
			want,
		)
	}
}
