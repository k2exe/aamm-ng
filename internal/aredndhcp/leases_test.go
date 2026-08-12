package aredndhcp

import (
	"errors"
	"testing"
)

func TestLookupReturnsHostnameForExactIPv4Lease(t *testing.T) {
	data := `1723400000 02:00:00:00:00:01 192.0.2.44 test-workstation 01:02:03
1723400100 02:00:00:00:00:02 192.0.2.45 test-tablet 01:04:05
`

	got, err := Lookup(
		data,
		"192.0.2.44",
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "test-workstation" {
		t.Fatalf(
			"hostname = %q; want test-workstation",
			got,
		)
	}
}

func TestLookupIgnoresMalformedLeaseRecords(t *testing.T) {
	data := `malformed
1723400000 02:00:00:00:00:01 192.0.2.44
1723400000 02:00:00:00:00:01 not-an-ip bad-host 01:02:03
1723400000 02:00:00:00:00:02 192.0.2.44 test-workstation 01:04:05
`

	got, err := Lookup(
		data,
		"192.0.2.44",
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "test-workstation" {
		t.Fatalf(
			"hostname = %q; want test-workstation",
			got,
		)
	}
}

func TestLookupReturnsEmptyWhenLeaseDoesNotExist(t *testing.T) {
	data := `1723400000 02:00:00:00:00:01 192.0.2.45 test-tablet 01:02:03
`

	got, err := Lookup(
		data,
		"192.0.2.44",
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "" {
		t.Fatalf(
			"hostname = %q; want empty",
			got,
		)
	}
}

func TestLookupRejectsInvalidSourceAddress(t *testing.T) {
	_, err := Lookup(
		"",
		"not-an-ip",
	)

	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf(
			"error = %v; want ErrInvalidSource",
			err,
		)
	}
}

func TestLookupRejectsIPv6SourceAddress(t *testing.T) {
	_, err := Lookup(
		"",
		"2001:db8::44",
	)

	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf(
			"error = %v; want ErrInvalidSource",
			err,
		)
	}
}

func TestLookupAllowsDuplicateEqualHostname(t *testing.T) {
	data := `1723400000 02:00:00:00:00:01 192.0.2.44 test-workstation 01:02:03
1723400100 02:00:00:00:00:02 192.0.2.44 test-workstation 01:04:05
`

	got, err := Lookup(
		data,
		"192.0.2.44",
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "test-workstation" {
		t.Fatalf(
			"hostname = %q; want test-workstation",
			got,
		)
	}
}

func TestLookupRejectsConflictingDuplicateHostname(t *testing.T) {
	data := `1723400000 02:00:00:00:00:01 192.0.2.44 test-workstation 01:02:03
1723400100 02:00:00:00:00:02 192.0.2.44 test-tablet 01:04:05
`

	_, err := Lookup(
		data,
		"192.0.2.44",
	)

	if !errors.Is(err, ErrAmbiguousLease) {
		t.Fatalf(
			"error = %v; want ErrAmbiguousLease",
			err,
		)
	}
}

func TestLookupTreatsNoHostnameMarkerAsEmpty(t *testing.T) {
	data := `1723400000 02:00:00:00:00:01 192.0.2.44 * 01:02:03
`

	got, err := Lookup(
		data,
		"192.0.2.44",
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "" {
		t.Fatalf(
			"hostname = %q; want empty",
			got,
		)
	}
}

func TestLookupIgnoresNoHostnameMarkerBeforeNamedDuplicate(
	t *testing.T,
) {
	data := `1723400000 02:00:00:00:00:01 192.0.2.44 * 01:02:03
1723400100 02:00:00:00:00:02 192.0.2.44 test-workstation 01:04:05
`

	got, err := Lookup(
		data,
		"192.0.2.44",
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "test-workstation" {
		t.Fatalf(
			"hostname = %q; want test-workstation",
			got,
		)
	}
}
