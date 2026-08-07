package webadmin

import (
	"context"
	"net/http"

	"github.com/k2exe/aamm-ng/internal/arednauth"
)

type SessionVerifier interface {
	Verify(context.Context, string) (bool, error)
}

func RequireAdmin(
	verifier SessionVerifier,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		setAuthResponseHeaders(writer)

		if verifier == nil {
			serviceUnavailable(writer)
			return
		}

		authenticated, err := verifier.Verify(
			request.Context(),
			arednauth.AuthV1FromRequest(request),
		)
		if err != nil {
			serviceUnavailable(writer)
			return
		}

		if !authenticated {
			unauthorized(writer)
			return
		}

		next.ServeHTTP(writer, request)
	})
}

func setAuthResponseHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set(
		"Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
	)
	writer.Header().Set("Referrer-Policy", "same-origin")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
}

func unauthorized(writer http.ResponseWriter) {
	http.Error(
		writer,
		"AREDN administrator login required.",
		http.StatusUnauthorized,
	)
}

func serviceUnavailable(writer http.ResponseWriter) {
	http.Error(
		writer,
		"AREDN authentication service unavailable.",
		http.StatusServiceUnavailable,
	)
}
