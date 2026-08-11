package webadmin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/arednauth"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
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
	request.Header.Set(
		auditidentity.SourceIPHeader,
		"192.0.2.44",
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

func TestRequireAdminAddsAuthenticatedIdentityToContext(t *testing.T) {
	verifier := &fakeVerifier{
		authenticated: true,
		name:          "TEST-NODE-A",
	}

	handler := RequireAdmin(
		verifier,
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			identity, ok := auditidentity.FromContext(
				request.Context(),
			)
			if !ok {
				t.Fatal("authenticated identity missing from context")
			}

			if identity.Name != "TEST-NODE-A" {
				t.Fatalf(
					"identity name = %q; want TEST-NODE-A",
					identity.Name,
				)
			}

			if identity.SourceIP != "192.0.2.44" {
				t.Fatalf(
					"identity source IP = %q; want 192.0.2.44",
					identity.SourceIP,
				)
			}

			if got := request.Header.Get(auditidentity.SourceIPHeader); got != "" {
				t.Fatalf(
					"trusted source header still present = %q",
					got,
				)
			}

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
		"authV1=sensitive-value",
	)
	request.Header.Set(
		auditidentity.SourceIPHeader,
		"192.0.2.44",
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
	request.Header.Set(
		auditidentity.SourceIPHeader,
		"192.0.2.44",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf(
			"Cache-Control = %q; want no-store",
			got,
		)
	}

	csp := response.Header().Get("Content-Security-Policy")

	for _, expected := range []string{
		"default-src 'self'",
		"img-src 'self' data:",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, expected) {
			t.Fatalf(
				"Content-Security-Policy missing %q: %q",
				expected,
				csp,
			)
		}
	}

	if got := response.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf(
			"Referrer-Policy = %q; want same-origin",
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

func TestRequireAdminFailsClosedWithoutSourceIP(t *testing.T) {
	verifier := &fakeVerifier{
		authenticated: true,
		name:          "TEST-NODE-A",
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
		"authV1=test-value",
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

func TestRequireAdminFailsClosedWithInvalidSourceIP(t *testing.T) {
	verifier := &fakeVerifier{
		authenticated: true,
		name:          "TEST-NODE-A",
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
		"authV1=test-value",
	)
	request.Header.Set(
		auditidentity.SourceIPHeader,
		"not-an-ip-address",
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

type fakeVerifier struct {
	authenticated bool
	name          string
	err           error
	value         string
}

func (verifier *fakeVerifier) VerifySession(
	_ context.Context,
	value string,
) (arednauth.Session, error) {
	verifier.value = value

	name := verifier.name
	if verifier.authenticated && name == "" {
		name = "node"
	}

	return arednauth.Session{
		Authenticated: verifier.authenticated,
		Name:          name,
	}, verifier.err
}
