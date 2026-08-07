package arednauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyWithoutCookieDoesNotMakeRequest(t *testing.T) {
	var requests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		},
	))
	defer server.Close()

	verifier := testVerifier(server.URL)

	authenticated, err := verifier.Verify(
		context.Background(),
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	if authenticated {
		t.Fatal("Verify() authenticated without authV1 cookie")
	}

	if got := requests.Load(); got != 0 {
		t.Fatalf("requests = %d; want 0", got)
	}
}

func TestVerifyAuthenticatedSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("method = %q; want GET", r.Method)
			}

			if got := r.Header.Get("Cookie"); got != "authV1=test-value" {
				t.Errorf(
					"Cookie = %q; want authV1=test-value",
					got,
				)
			}

			w.Header().Set(
				"Set-Cookie",
				"authV1=replacement; Path=/",
			)

			_, _ = w.Write([]byte(
				`{"name":"node","authenticated":true,"portableTheme":false}`,
			))
		},
	))
	defer server.Close()

	verifier := testVerifier(server.URL)

	authenticated, err := verifier.Verify(
		context.Background(),
		"test-value",
	)
	if err != nil {
		t.Fatal(err)
	}

	if !authenticated {
		t.Fatal("Verify() = false; want true")
	}
}

func TestVerifyUnauthenticatedSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(
				`{"authenticated":false}`,
			))
		},
	))
	defer server.Close()

	verifier := testVerifier(server.URL)

	authenticated, err := verifier.Verify(
		context.Background(),
		"test-value",
	)
	if err != nil {
		t.Fatal(err)
	}

	if authenticated {
		t.Fatal("Verify() = true; want false")
	}
}

func TestVerifyRejectsUnsafeCookieValue(t *testing.T) {
	verifier := testVerifier("http://127.0.0.1/unused")

	for _, value := range []string{
		"bad\rvalue",
		"bad\nvalue",
		"bad;value",
	} {
		t.Run(value, func(t *testing.T) {
			authenticated, err := verifier.Verify(
				context.Background(),
				value,
			)
			if err != nil {
				t.Fatal(err)
			}

			if authenticated {
				t.Fatal("Verify() authenticated unsafe cookie")
			}
		})
	}
}

func TestVerifyRejectsRedirect(t *testing.T) {
	targetRequests := atomic.Int32{}

	target := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			targetRequests.Add(1)
			_, _ = w.Write([]byte(
				`{"authenticated":true}`,
			))
		},
	))
	defer target.Close()

	redirect := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(
				w,
				r,
				target.URL,
				http.StatusFound,
			)
		},
	))
	defer redirect.Close()

	verifier := testVerifier(redirect.URL)

	authenticated, err := verifier.Verify(
		context.Background(),
		"test-value",
	)

	if authenticated {
		t.Fatal("Verify() authenticated redirect")
	}

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}

	if got := targetRequests.Load(); got != 0 {
		t.Fatalf(
			"redirect target requests = %d; want 0",
			got,
		)
	}
}

func TestVerifyRejectsNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(
				w,
				"failure",
				http.StatusServiceUnavailable,
			)
		},
	))
	defer server.Close()

	verifier := testVerifier(server.URL)

	_, err := verifier.Verify(
		context.Background(),
		"test-value",
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}
}

func TestVerifyRejectsMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not-json`))
		},
	))
	defer server.Close()

	verifier := testVerifier(server.URL)

	_, err := verifier.Verify(
		context.Background(),
		"test-value",
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}
}

func TestVerifyRequiresAuthenticatedField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(
				`{"name":"node"}`,
			))
		},
	))
	defer server.Close()

	verifier := testVerifier(server.URL)

	_, err := verifier.Verify(
		context.Background(),
		"test-value",
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}
}

func TestVerifyRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(
				strings.Repeat("x", maxResponseBytes+1),
			))
		},
	))
	defer server.Close()

	verifier := testVerifier(server.URL)

	_, err := verifier.Verify(
		context.Background(),
		"test-value",
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}
}

func TestVerifyFailsWhenVerifierUnavailable(t *testing.T) {
	verifier := testVerifier(
		"http://127.0.0.1:1/a/whoami",
	)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancel()

	_, err := verifier.Verify(ctx, "test-value")

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf(
			"error = %v; want ErrUnavailable",
			err,
		)
	}
}

func testVerifier(endpoint string) *Verifier {
	verifier := NewVerifier()
	verifier.endpoint = endpoint
	return verifier
}
