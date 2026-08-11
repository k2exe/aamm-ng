package arednnodes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetcherReturnsLocalNodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("method = %q; want GET", r.Method)
			}

			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Errorf(
					"Accept = %q; want application/json",
					got,
				)
			}

			w.Header().Set("Content-Type", "application/json")

			_, _ = w.Write([]byte(`{
				"lqm":{
					"info":{
						"trackers":{
							"02:00:00:00:00:01":{
								"hostname":"TEST-NODE-B",
								"type":"RF"
							},
							"02:00:00:00:00:02":{
								"hostname":"TEST-NODE-A",
								"type":"DtD"
							}
						}
					}
				}
			}`))
		},
	))
	defer server.Close()

	fetcher := testFetcher(server.URL)

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

func TestFetcherRejectsNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			http.Error(
				w,
				"internal detail must not be propagated",
				http.StatusServiceUnavailable,
			)
		},
	))
	defer server.Close()

	fetcher := testFetcher(server.URL)

	_, err := fetcher.LocalNodes(context.Background())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}

	if strings.Contains(
		err.Error(),
		"internal detail",
	) {
		t.Fatalf("error leaked response content: %v", err)
	}
}

func TestFetcherRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(
				[]byte(strings.Repeat(
					"x",
					maxResponseBytes+1,
				)),
			)
		},
	))
	defer server.Close()

	fetcher := testFetcher(server.URL)

	_, err := fetcher.LocalNodes(context.Background())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}
}

func TestFetcherRejectsMalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"lqm":`))
		},
	))
	defer server.Close()

	fetcher := testFetcher(server.URL)

	_, err := fetcher.LocalNodes(context.Background())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}

	if strings.Contains(err.Error(), `{"lqm":`) {
		t.Fatalf("error leaked response content: %v", err)
	}
}

func TestFetcherDoesNotFollowRedirects(t *testing.T) {
	var destinationCalls atomic.Int32

	destination := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			destinationCalls.Add(1)
			_, _ = w.Write([]byte(`{"lqm":{"info":{"trackers":{}}}}`))
		},
	))
	defer destination.Close()

	redirector := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(
				w,
				r,
				destination.URL,
				http.StatusFound,
			)
		},
	))
	defer redirector.Close()

	fetcher := testFetcher(redirector.URL)

	_, err := fetcher.LocalNodes(context.Background())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}

	if got := destinationCalls.Load(); got != 0 {
		t.Fatalf(
			"redirect destination calls = %d; want 0",
			got,
		)
	}
}

func TestFetcherFailsWhenEndpointUnavailable(t *testing.T) {
	fetcher := testFetcher(
		"http://127.0.0.1:1/a/sysinfo?lqm=1",
	)

	_, err := fetcher.LocalNodes(context.Background())

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf(
			"error = %v; want ErrUnavailable",
			err,
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

func testFetcher(endpoint string) *Fetcher {
	fetcher := NewFetcher()
	fetcher.endpoint = endpoint

	return fetcher
}

func TestProductionEndpointIsFixedLoopback(t *testing.T) {
	endpoint, err := url.Parse(ProductionEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	if endpoint.Scheme != "http" {
		t.Fatalf(
			"scheme = %q; want http",
			endpoint.Scheme,
		)
	}

	if endpoint.Host != "127.0.0.1" {
		t.Fatalf(
			"host = %q; want fixed IPv4 loopback",
			endpoint.Host,
		)
	}

	if endpoint.User != nil {
		t.Fatal("production endpoint contains user information")
	}

	if endpoint.Path != "/a/sysinfo" {
		t.Fatalf(
			"path = %q; want /a/sysinfo",
			endpoint.Path,
		)
	}

	if endpoint.RawQuery != "lqm=1" {
		t.Fatalf(
			"query = %q; want lqm=1",
			endpoint.RawQuery,
		)
	}
}
