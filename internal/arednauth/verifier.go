package arednauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// ProductionEndpoint is deliberately fixed to AREDN's loopback-only
	// authentication endpoint. The authV1 credential is derived from the
	// root entry in /etc/shadow; never make this endpoint configurable or
	// forward authV1 to a non-loopback destination.
	ProductionEndpoint = "http://127.0.0.1/a/whoami"

	maxResponseBytes = 4096
	requestTimeout   = 2 * time.Second
)

var (
	ErrUnavailable     = errors.New("AREDN authentication verifier unavailable")
	ErrInvalidResponse = errors.New("invalid AREDN authentication response")
)

type Session struct {
	Authenticated bool
	Name          string
}

type Verifier struct {
	endpoint string
	client   *http.Client
}

func NewVerifier() *Verifier {
	dialer := &net.Dialer{
		Timeout: requestTimeout,
	}

	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
	}

	return &Verifier{
		endpoint: ProductionEndpoint,
		client: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			CheckRedirect: func(
				_ *http.Request,
				_ []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (v *Verifier) Verify(
	ctx context.Context,
	authV1 string,
) (bool, error) {
	session, err := v.VerifySession(ctx, authV1)
	if err != nil {
		return false, err
	}

	return session.Authenticated, nil
}

func (v *Verifier) VerifySession(
	ctx context.Context,
	authV1 string,
) (Session, error) {
	// authV1 is credential-equivalent material derived by AREDN from the
	// root /etc/shadow entry. Never log, persist, include it in errors, or
	// forward it anywhere except the fixed loopback authentication endpoint.
	if authV1 == "" {
		return Session{}, nil
	}

	if strings.ContainsAny(authV1, "\r\n;") {
		return Session{}, nil
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		v.endpoint,
		nil,
	)
	if err != nil {
		return Session{}, fmt.Errorf(
			"%w: create request",
			ErrUnavailable,
		)
	}

	request.Header.Set("Cookie", "authV1="+authV1)

	response, err := v.client.Do(request)
	if err != nil {
		return Session{}, fmt.Errorf(
			"%w: request failed",
			ErrUnavailable,
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Session{}, fmt.Errorf(
			"%w: unexpected HTTP status %d",
			ErrInvalidResponse,
			response.StatusCode,
		)
	}

	body, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maxResponseBytes+1,
		),
	)
	if err != nil {
		return Session{}, fmt.Errorf(
			"%w: read response",
			ErrUnavailable,
		)
	}

	if len(body) > maxResponseBytes {
		return Session{}, fmt.Errorf(
			"%w: response exceeds %d bytes",
			ErrInvalidResponse,
			maxResponseBytes,
		)
	}

	var result struct {
		Name          string `json:"name"`
		Authenticated *bool  `json:"authenticated"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return Session{}, fmt.Errorf(
			"%w: malformed JSON",
			ErrInvalidResponse,
		)
	}

	if result.Authenticated == nil {
		return Session{}, fmt.Errorf(
			"%w: authenticated field missing",
			ErrInvalidResponse,
		)
	}

	if !*result.Authenticated {
		return Session{}, nil
	}

	if strings.TrimSpace(result.Name) == "" {
		return Session{}, fmt.Errorf(
			"%w: authenticated name missing",
			ErrInvalidResponse,
		)
	}

	return Session{
		Authenticated: true,
		Name:          result.Name,
	}, nil
}
