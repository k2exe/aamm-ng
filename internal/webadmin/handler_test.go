package webadmin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesAuthenticatedLandingPage(t *testing.T) {
	handler := NewHandler(&fakeVerifier{
		authenticated: true,
	})

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)
	request.Header.Set(
		"Cookie",
		"authV1=test-value",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusOK,
		)
	}

	if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf(
			"Content-Type = %q; want text/html; charset=utf-8",
			got,
		)
	}

	if !strings.Contains(
		response.Body.String(),
		"AREDN Alert Message Manager",
	) {
		t.Fatal("landing page content missing")
	}

	if strings.Contains(
		response.Body.String(),
		"test-value",
	) {
		t.Fatal("landing page leaked authV1 value")
	}
}

func TestHandlerSupportsHEAD(t *testing.T) {
	handler := NewHandler(&fakeVerifier{
		authenticated: true,
	})

	request := httptest.NewRequest(
		http.MethodHead,
		"http://node.local.mesh/",
		nil,
	)
	request.Header.Set(
		"Cookie",
		"authV1=test-value",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusOK,
		)
	}

	if response.Body.Len() != 0 {
		t.Fatalf(
			"body length = %d; want 0",
			response.Body.Len(),
		)
	}
}

func TestHandlerRejectsUnsupportedMethod(t *testing.T) {
	handler := NewHandler(&fakeVerifier{
		authenticated: true,
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh/",
		nil,
	)
	request.Header.Set(
		"Cookie",
		"authV1=test-value",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusMethodNotAllowed,
		)
	}

	if got := response.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf(
			"Allow = %q; want GET, HEAD",
			got,
		)
	}
}

func TestHandlerReturnsNotFoundForUnknownPath(t *testing.T) {
	handler := NewHandler(&fakeVerifier{
		authenticated: true,
	})

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/not-found",
		nil,
	)
	request.Header.Set(
		"Cookie",
		"authV1=test-value",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusNotFound,
		)
	}
}

func TestHandlerDoesNotExposeLandingPageWithoutAuthentication(t *testing.T) {
	handler := NewHandler(&fakeVerifier{})

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusUnauthorized,
		)
	}

	if strings.Contains(
		response.Body.String(),
		"AREDN Alert Message Manager",
	) {
		t.Fatal("unauthenticated response exposed protected page")
	}
}
