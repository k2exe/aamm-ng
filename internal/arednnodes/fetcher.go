package arednnodes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	// ProductionEndpoint is deliberately fixed to the local AREDN node's
	// sysinfo LQM endpoint. Node discovery must not query mesh-wide or
	// cloud/supernode node-list endpoints.
	ProductionEndpoint = "http://127.0.0.1/a/sysinfo?lqm=1"

	maxResponseBytes = 256 * 1024
	requestTimeout   = 2 * time.Second
)

var (
	ErrUnavailable     = errors.New("AREDN local node discovery unavailable")
	ErrInvalidResponse = errors.New("invalid AREDN local node discovery response")
)

type Fetcher struct {
	endpoint string
	client   *http.Client
}

func NewFetcher() *Fetcher {
	dialer := &net.Dialer{
		Timeout: requestTimeout,
	}

	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
	}

	return &Fetcher{
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

func (f *Fetcher) LocalNodes(
	ctx context.Context,
) ([]string, error) {
	if f == nil ||
		f.client == nil ||
		f.endpoint == "" {
		return nil, ErrUnavailable
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		f.endpoint,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: create request",
			ErrUnavailable,
		)
	}

	request.Header.Set("Accept", "application/json")

	response, err := f.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: request failed",
			ErrUnavailable,
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
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
		return nil, fmt.Errorf(
			"%w: read response",
			ErrUnavailable,
		)
	}

	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf(
			"%w: response exceeds %d bytes",
			ErrInvalidResponse,
			maxResponseBytes,
		)
	}

	nodes, err := ParseLocalNodes(body)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: malformed LQM data",
			ErrInvalidResponse,
		)
	}

	return nodes, nil
}
