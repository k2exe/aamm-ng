package aredndhcp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReaderLookupReturnsHostname(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"dhcp.leases",
	)

	data := `1723400000 02:00:00:00:00:01 192.0.2.44 test-workstation 01:02:03
`

	if err := os.WriteFile(
		path,
		[]byte(data),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	r := reader{
		path:     path,
		maxBytes: 1024,
	}

	got, err := r.lookup("192.0.2.44")
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

func TestReaderLookupMissingFileIsUnavailable(t *testing.T) {
	r := reader{
		path: filepath.Join(
			t.TempDir(),
			"missing.leases",
		),
		maxBytes: 1024,
	}

	_, err := r.lookup("192.0.2.44")

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf(
			"error = %v; want ErrUnavailable",
			err,
		)
	}
}

func TestReaderRejectsSymlink(t *testing.T) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"target.leases",
	)
	link := filepath.Join(
		directory,
		"dhcp.leases",
	)

	if err := os.WriteFile(
		target,
		[]byte(
			"1723400000 02:00:00:00:00:01 192.0.2.44 test-workstation 01:02:03\n",
		),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	r := reader{
		path:     link,
		maxBytes: 1024,
	}

	_, err := r.lookup("192.0.2.44")

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf(
			"error = %v; want ErrUnavailable",
			err,
		)
	}
}

func TestReaderRejectsNonRegularFile(t *testing.T) {
	r := reader{
		path:     t.TempDir(),
		maxBytes: 1024,
	}

	_, err := r.lookup("192.0.2.44")

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf(
			"error = %v; want ErrUnavailable",
			err,
		)
	}
}

func TestReaderRejectsOversizedLeaseFile(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"dhcp.leases",
	)

	if err := os.WriteFile(
		path,
		[]byte("0123456789abcdef"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	r := reader{
		path:     path,
		maxBytes: 8,
	}

	_, err := r.lookup("192.0.2.44")

	if !errors.Is(err, ErrDataTooLarge) {
		t.Fatalf(
			"error = %v; want ErrDataTooLarge",
			err,
		)
	}
}

func TestDefaultReaderUsesFixedProductionLeaseFile(t *testing.T) {
	r := defaultReader()

	if r.path != defaultLeasePath {
		t.Fatalf(
			"path = %q; want %q",
			r.path,
			defaultLeasePath,
		)
	}

	if r.maxBytes != defaultMaxLeaseBytes {
		t.Fatalf(
			"max bytes = %d; want %d",
			r.maxBytes,
			defaultMaxLeaseBytes,
		)
	}
}
