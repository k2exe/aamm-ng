package webadmin

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServeHandlesHTTPAndStopsOnCancellation(t *testing.T) {
	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- Serve(
			ctx,
			listener,
			http.HandlerFunc(
				func(
					writer http.ResponseWriter,
					request *http.Request,
				) {
					writer.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(
						writer,
						"ready",
					)
				},
			),
		)
	}()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	response, err := client.Get(
		"http://" + listener.Addr().String(),
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	body, err := io.ReadAll(response.Body)
	response.Body.Close()

	if err != nil {
		cancel()
		t.Fatal(err)
	}

	if response.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf(
			"status = %d; want %d",
			response.StatusCode,
			http.StatusOK,
		)
	}

	if string(body) != "ready" {
		cancel()
		t.Fatalf(
			"body = %q; want ready",
			string(body),
		)
	}

	cancel()

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf(
				"Serve returned error: %v",
				err,
			)
		}

	case <-time.After(5 * time.Second):
		t.Fatal(
			"Serve did not stop after cancellation",
		)
	}
}

func TestServeRejectsInvalidConfiguration(t *testing.T) {
	handler := http.HandlerFunc(
		func(
			http.ResponseWriter,
			*http.Request,
		) {
		},
	)

	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tests := map[string]struct {
		ctx      context.Context
		listener net.Listener
		handler  http.Handler
	}{
		"nil context": {
			listener: listener,
			handler:  handler,
		},
		"nil listener": {
			ctx:     context.Background(),
			handler: handler,
		},
		"nil handler": {
			ctx:      context.Background(),
			listener: listener,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := Serve(
				test.ctx,
				test.listener,
				test.handler,
			)

			if !errors.Is(err, ErrInvalidServer) {
				t.Fatalf(
					"error = %v; want ErrInvalidServer",
					err,
				)
			}
		})
	}
}

func TestServeReturnsListenerFailure(t *testing.T) {
	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	err = Serve(
		context.Background(),
		listener,
		http.HandlerFunc(
			func(
				http.ResponseWriter,
				*http.Request,
			) {
			},
		),
	)

	if err == nil {
		t.Fatal(
			"Serve returned nil for closed listener",
		)
	}

	if !strings.Contains(
		err.Error(),
		"closed",
	) {
		t.Fatalf(
			"error = %v; want closed-listener error",
			err,
		)
	}
}
