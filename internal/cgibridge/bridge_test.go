package cgibridge

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNewRequestPreservesBrowserOrigin(t *testing.T) {
	values := map[string]string{
		"REQUEST_METHOD": "POST",
		"PATH_INFO":      "/alerts/wx",
		"QUERY_STRING":   "test=1",
		"HTTP_HOST":      "node.local.mesh",
		"HTTP_COOKIE":    "authV1=test-cookie",
		"HTTP_ORIGIN":    "http://node.local.mesh",
		"CONTENT_TYPE":   "application/x-www-form-urlencoded",
		"CONTENT_LENGTH": "12",
	}

	request, err := newRequest(
		context.Background(),
		strings.NewReader("message=test"),
		func(name string) string {
			return values[name]
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := request.URL.Host; got != BackendAddress {
		t.Fatalf(
			"backend host = %q; want %q",
			got,
			BackendAddress,
		)
	}

	if got := request.URL.Path; got != "/alerts/wx" {
		t.Fatalf(
			"path = %q; want /alerts/wx",
			got,
		)
	}

	if got := request.Host; got != "node.local.mesh" {
		t.Fatalf(
			"Host = %q; want node.local.mesh",
			got,
		)
	}

	if got := request.Header.Get("Origin"); got != "http://node.local.mesh" {
		t.Fatalf(
			"Origin = %q; want browser origin",
			got,
		)
	}

	if got := request.Header.Get("Cookie"); got != "authV1=test-cookie" {
		t.Fatalf(
			"Cookie = %q; want authV1 cookie",
			got,
		)
	}

	if got := request.Header.Get("X-Forwarded-Prefix"); got != ExternalBasePath {
		t.Fatalf(
			"X-Forwarded-Prefix = %q; want %q",
			got,
			ExternalBasePath,
		)
	}

	if request.ContentLength != 12 {
		t.Fatalf(
			"ContentLength = %d; want 12",
			request.ContentLength,
		)
	}
}

func TestNewRequestUsesRootForEmptyPathInfo(t *testing.T) {
	request, err := newRequest(
		context.Background(),
		http.NoBody,
		func(name string) string {
			switch name {
			case "REQUEST_METHOD":
				return "GET"
			case "HTTP_HOST":
				return "node.local.mesh"
			default:
				return ""
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if request.URL.Path != "/" {
		t.Fatalf(
			"path = %q; want /",
			request.URL.Path,
		)
	}
}

func TestRewriteLocation(t *testing.T) {
	got := rewriteLocation("/alerts/wx")

	want := ExternalBasePath + "/alerts/wx"

	if got != want {
		t.Fatalf(
			"rewriteLocation = %q; want %q",
			got,
			want,
		)
	}
}

func TestWriteResponsePreservesSecurityHeaders(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusSeeOther,
		Header: http.Header{
			"Location":        {"/alerts/wx"},
			"Referrer-Policy": {"same-origin"},
			"Content-Length":  {"999"},
		},
		Body: io.NopCloser(
			strings.NewReader("redirect"),
		),
	}

	var output bytes.Buffer

	if err := writeResponse(
		&output,
		response,
	); err != nil {
		t.Fatal(err)
	}

	got := output.String()

	checks := []string{
		"Status: 303 See Other\r\n",
		"Location: " + ExternalBasePath + "/alerts/wx\r\n",
		"Referrer-Policy: same-origin\r\n",
		"\r\nredirect",
	}

	for _, value := range checks {
		if !strings.Contains(got, value) {
			t.Fatalf(
				"CGI response missing %q:\n%s",
				value,
				got,
			)
		}
	}

	if strings.Contains(got, "Content-Length:") {
		t.Fatalf(
			"CGI response unexpectedly forwarded Content-Length:\n%s",
			got,
		)
	}
}
