package localcontrol

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
)

func TestClientCreateSendsCanonicalRequest(t *testing.T) {
	socketPath := filepath.Join(
		t.TempDir(),
		"control.sock",
	)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)

	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer connection.Close()

		line, err := bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			serverErr <- err
			return
		}

		request, err := DecodeRequest(
			line[:len(line)-1],
		)
		if err != nil {
			serverErr <- err
			return
		}

		if request.Operation != OperationCreate {
			serverErr <- errors.New("unexpected operation")
			return
		}

		if request.Target != "all" {
			serverErr <- errors.New(
				"target was not canonicalized",
			)
			return
		}

		if request.Message != "Line one\nLine two" {
			serverErr <- errors.New(
				"message was not canonicalized",
			)
			return
		}

		_, err = io.WriteString(
			connection,
			`{"version":1,"ok":true,"result":`+
				`{"target":"all","kind":"managed"}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.Create(
		context.Background(),
		"ALL",
		"Line one\r\nLine two",
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("test server: %v", err)
	}

	if result.Target != "all" {
		t.Fatalf(
			"Target = %q; want all",
			result.Target,
		)
	}

	if result.Kind != "managed" {
		t.Fatalf(
			"Kind = %q; want managed",
			result.Kind,
		)
	}
}

func TestClientCreateRejectsInvalidTargetBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Create(
		context.Background(),
		"../etc/passwd",
		"Net open",
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}
