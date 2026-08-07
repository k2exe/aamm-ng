package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	listening := make(chan struct{})

	listen := func() (net.Listener, error) {
		listener, err := net.Listen(
			"tcp4",
			"127.0.0.1:0",
		)
		if err != nil {
			return nil, err
		}

		close(listening)

		return listener, nil
	}

	var stdout bytes.Buffer
	done := make(chan error, 1)

	go func() {
		done <- run(
			ctx,
			&stdout,
			listen,
		)
	}()

	select {
	case <-listening:
	case <-time.After(time.Second):
		t.Fatal("web service did not create listener")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf(
				"run() error = %v; want nil",
				err,
			)
		}

	case <-time.After(time.Second):
		t.Fatal(
			"web service did not stop after cancellation",
		)
	}

	output := stdout.String()

	if !strings.Contains(
		output,
		"AAMM-NG web started",
	) {
		t.Fatalf(
			"stdout = %q; want startup message",
			output,
		)
	}

	if !strings.Contains(
		output,
		"AAMM-NG web stopped",
	) {
		t.Fatalf(
			"stdout = %q; want shutdown message",
			output,
		)
	}
}

func TestRunReturnsListenerFailure(t *testing.T) {
	expected := errors.New(
		"listener unavailable",
	)

	err := run(
		context.Background(),
		&bytes.Buffer{},
		func() (net.Listener, error) {
			return nil, expected
		},
	)

	if !errors.Is(err, expected) {
		t.Fatalf(
			"run() error = %v; want listener error",
			err,
		)
	}
}
