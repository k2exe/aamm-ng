package arednauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthV1FromRequest(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)

	request.Header.Set(
		"Cookie",
		"other=ignore-me; authV1=test-value; another=ignore-too",
	)

	if got := AuthV1FromRequest(request); got != "test-value" {
		t.Fatalf(
			"AuthV1FromRequest() = %q; want test-value",
			got,
		)
	}
}

func TestAuthV1FromRequestMissing(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)

	if got := AuthV1FromRequest(request); got != "" {
		t.Fatalf(
			"AuthV1FromRequest() = %q; want empty",
			got,
		)
	}
}

func TestAuthV1FromRequestNilRequest(t *testing.T) {
	if got := AuthV1FromRequest(nil); got != "" {
		t.Fatalf(
			"AuthV1FromRequest(nil) = %q; want empty",
			got,
		)
	}
}

func TestAuthV1FromRequestUsesFirstMatchingCookie(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)

	request.Header.Set(
		"Cookie",
		"authV1=first; authV1=second",
	)

	if got := AuthV1FromRequest(request); got != "first" {
		t.Fatalf(
			"AuthV1FromRequest() = %q; want first",
			got,
		)
	}
}

func TestAuthV1FromRequestDoesNotReturnOtherCookies(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)

	request.Header.Set(
		"Cookie",
		"session=secret; preference=value",
	)

	if got := AuthV1FromRequest(request); got != "" {
		t.Fatalf(
			"AuthV1FromRequest() = %q; want empty",
			got,
		)
	}
}
