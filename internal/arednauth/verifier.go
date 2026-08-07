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
	ProductionEndpoint = "http://127.0.0.1/a/whoami"

	maxResponseBytes = 4096
	requestTimeout   = 2 * time.Second
)

var (
	ErrUnavailable     = errors.New("AREDN authentication verifier unavailable")
	ErrInvalidResponse = errors.New("invalid AREDN authentication response")
)

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
	if authV1 == "" {
		return false, nil
	}

	if strings.ContainsAny(authV1, "\r\n;") {
		return false, nil
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		v.endpoint,
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("%w: create request", ErrUnavailable)
	}

	request.Header.Set("Cookie", "authV1="+authV1)

	response, err := v.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("%w: request failed", ErrUnavailable)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf(
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
		return false, fmt.Errorf("%w: read response", ErrUnavailable)
	}

	if len(body) > maxResponseBytes {
		return false, fmt.Errorf(
			"%w: response exceeds %d bytes",
			ErrInvalidResponse,
			maxResponseBytes,
		)
	}

	var result struct {
		Authenticated *bool `json:"authenticated"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf(
			"%w: malformed JSON",
			ErrInvalidResponse,
		)
	}

	if result.Authenticated == nil {
		return false, fmt.Errorf(
			"%w: authenticated field missing",
			ErrInvalidResponse,
		)
	}

	return *result.Authenticated, nil
}
