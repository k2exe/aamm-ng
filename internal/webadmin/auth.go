package webadmin

import (
	"context"
	"net/http"
	"net/netip"
	"strings"

	"github.com/k2exe/aamm-ng/internal/arednauth"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
)

type SessionVerifier interface {
	VerifySession(context.Context, string) (arednauth.Session, error)
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

		session, err := verifier.VerifySession(
			request.Context(),
			arednauth.AuthV1FromRequest(request),
		)
		if err != nil {
			serviceUnavailable(writer)
			return
		}

		if !session.Authenticated {
			unauthorized(writer)
			return
		}

		if strings.TrimSpace(session.Name) == "" {
			serviceUnavailable(writer)
			return
		}

		sourceIP, ok := trustedSourceIP(request)
		if !ok {
			serviceUnavailable(writer)
			return
		}

		ctx := auditidentity.WithIdentity(
			request.Context(),
			auditidentity.Identity{
				Name:     session.Name,
				SourceIP: sourceIP,
			},
		)

		nextRequest := request.WithContext(ctx)
		nextRequest.Header = request.Header.Clone()
		nextRequest.Header.Del(auditidentity.SourceIPHeader)

		next.ServeHTTP(
			writer,
			nextRequest,
		)
	})
}

func trustedSourceIP(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}

	address, err := netip.ParseAddr(
		request.Header.Get(auditidentity.SourceIPHeader),
	)
	if err != nil {
		return "", false
	}

	return address.Unmap().String(), true
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
