package arednnodes

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/k2exe/aamm-ng/internal/arednhosts"
)

func TestFetcherReturnsNodesFromLocalHostRecords(t *testing.T) {
	fetcher := &Fetcher{
		readRecords: func() ([]string, error) {
			return []string{
				`##192.0.2.10##
192.0.2.10 TEST-NODE-B
198.51.100.10 test-device-b

##192.0.2.20##
192.0.2.20 TEST-NODE-A
`,
			}, nil
		},
	}

	got, err := fetcher.LocalNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"test-node-a",
		"test-node-b",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"nodes = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestFetcherReturnsUnavailableWhenHostRecordsCannotBeRead(
	t *testing.T,
) {
	fetcher := &Fetcher{
		readRecords: func() ([]string, error) {
			return nil, errors.New("synthetic read failure")
		},
	}

	_, err := fetcher.LocalNodes(context.Background())

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf(
			"error = %v; want ErrUnavailable",
			err,
		)
	}
}

func TestFetcherDoesNotLeakReaderError(t *testing.T) {
	fetcher := &Fetcher{
		readRecords: func() ([]string, error) {
			return nil, errors.New("sensitive synthetic detail")
		},
	}

	_, err := fetcher.LocalNodes(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}

	if errors.Is(err, arednhosts.ErrDataTooLarge) {
		t.Fatalf(
			"internal reader error classification leaked: %v",
			err,
		)
	}

	if err.Error() !=
		"AREDN local node discovery unavailable: read local host records" {
		t.Fatalf(
			"error = %q; want sanitized discovery error",
			err.Error(),
		)
	}
}

func TestFetcherRejectsInvalidConfiguration(t *testing.T) {
	var fetcher Fetcher

	_, err := fetcher.LocalNodes(context.Background())

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf(
			"error = %v; want ErrUnavailable",
			err,
		)
	}
}

func TestNewFetcherUsesProductionReader(t *testing.T) {
	fetcher := NewFetcher()

	if fetcher == nil {
		t.Fatal("NewFetcher returned nil")
	}

	if fetcher.readRecords == nil {
		t.Fatal("NewFetcher has no host-record reader")
	}
}
