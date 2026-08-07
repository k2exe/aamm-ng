package webadmin

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameOriginAcceptsExactHTTPOrigin(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		nil,
	)

	request.Header.Set(
		"Origin",
		"http://node.local.mesh:11313",
	)

	if !sameOrigin(request) {
		t.Fatal("sameOrigin() = false; want true")
	}
}

func TestSameOriginRequiresPortMatch(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		nil,
	)

	request.Header.Set(
		"Origin",
		"http://node.local.mesh",
	)

	if sameOrigin(request) {
		t.Fatal("sameOrigin() accepted different port")
	}
}

func TestSameOriginRejectsDifferentHost(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		nil,
	)

	request.Header.Set(
		"Origin",
		"http://other.local.mesh:11313",
	)

	if sameOrigin(request) {
		t.Fatal("sameOrigin() accepted different host")
	}
}

func TestSameOriginRejectsDifferentScheme(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		nil,
	)

	request.Header.Set(
		"Origin",
		"https://node.local.mesh:11313",
	)

	if sameOrigin(request) {
		t.Fatal("sameOrigin() accepted different scheme")
	}
}

func TestSameOriginRejectsMissingOrigin(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		nil,
	)

	if sameOrigin(request) {
		t.Fatal("sameOrigin() accepted missing Origin")
	}
}

func TestSameOriginRejectsOriginWithPath(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		nil,
	)

	request.Header.Set(
		"Origin",
		"http://node.local.mesh:11313/anything",
	)

	if sameOrigin(request) {
		t.Fatal("sameOrigin() accepted Origin containing path")
	}
}

func TestSameOriginRejectsNullOrigin(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		nil,
	)

	request.Header.Set("Origin", "null")

	if sameOrigin(request) {
		t.Fatal("sameOrigin() accepted null Origin")
	}
}

func TestSameOriginSupportsHTTPS(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"https://node.local.mesh:11313/alerts/all",
		nil,
	)

	request.TLS = &tls.ConnectionState{}

	request.Header.Set(
		"Origin",
		"https://node.local.mesh:11313",
	)

	if !sameOrigin(request) {
		t.Fatal("sameOrigin() = false; want true")
	}
}

func TestSameOriginNilRequest(t *testing.T) {
	if sameOrigin(nil) {
		t.Fatal("sameOrigin(nil) = true; want false")
	}
}
