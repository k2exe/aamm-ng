package webadmin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireAdminAllowsAuthenticatedRequest(t *testing.T) {
	verifier := &fakeVerifier{
		authenticated: true,
	}

	nextCalls := 0

	handler := RequireAdmin(
		verifier,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			nextCalls++
			writer.WriteHeader(http.StatusOK)
		}),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)
	request.Header.Set(
		"Cookie",
		"other=ignore; authV1=test-value",
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

	if nextCalls != 1 {
		t.Fatalf(
			"next calls = %d; want 1",
			nextCalls,
		)
	}

	if verifier.value != "test-value" {
		t.Fatalf(
			"verifier value = %q; want test-value",
			verifier.value,
		)
	}
}

func TestRequireAdminRejectsMissingSession(t *testing.T) {
	verifier := &fakeVerifier{}

	handler := RequireAdmin(
		verifier,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			t.Fatal("protected handler called")
		}),
	)

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

	if verifier.value != "" {
		t.Fatalf(
			"verifier value = %q; want empty",
			verifier.value,
		)
	}
}

func TestRequireAdminRejectsInvalidSession(t *testing.T) {
	verifier := &fakeVerifier{
		authenticated: false,
	}

	handler := RequireAdmin(
		verifier,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			t.Fatal("protected handler called")
		}),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)
	request.Header.Set(
		"Cookie",
		"authV1=invalid-value",
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
}

func TestRequireAdminFailsClosedWhenVerifierFails(t *testing.T) {
	verifier := &fakeVerifier{
		err: errors.New("verification failed"),
	}

	handler := RequireAdmin(
		verifier,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			t.Fatal("protected handler called")
		}),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)
	request.Header.Set(
		"Cookie",
		"authV1=sensitive-value",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusServiceUnavailable,
		)
	}

	if strings.Contains(
		response.Body.String(),
		"sensitive-value",
	) {
		t.Fatal("response leaked authV1 value")
	}
}

func TestRequireAdminFailsClosedWithoutVerifier(t *testing.T) {
	handler := RequireAdmin(
		nil,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			t.Fatal("protected handler called")
		}),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
		nil,
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusServiceUnavailable,
		)
	}
}

func TestRequireAdminSetsNoStoreHeaders(t *testing.T) {
	verifier := &fakeVerifier{
		authenticated: true,
	}

	handler := RequireAdmin(
		verifier,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			writer.WriteHeader(http.StatusOK)
		}),
	)

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

	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf(
			"Cache-Control = %q; want no-store",
			got,
		)
	}

	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf(
			"X-Content-Type-Options = %q; want nosniff",
			got,
		)
	}
}

type fakeVerifier struct {
	authenticated bool
	err           error
	value         string
}

func (verifier *fakeVerifier) Verify(
	_ context.Context,
	value string,
) (bool, error) {
	verifier.value = value

	return verifier.authenticated, verifier.err
}
