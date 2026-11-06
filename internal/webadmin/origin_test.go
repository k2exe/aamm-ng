package webadmin

import (
	http "github.com/k2exe/aamm-ng/internal/minihttp"
	"github.com/k2exe/aamm-ng/internal/minihttp/httptest"
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

func TestSameOriginRejectsHTTPSOrigin(t *testing.T) {
	// AAMM-NG is plain HTTP only; an https Origin never matches.
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
		t.Fatal("sameOrigin() accepted https Origin")
	}
}

func TestSameOriginNilRequest(t *testing.T) {
	if sameOrigin(nil) {
		t.Fatal("sameOrigin(nil) = true; want false")
	}
}
