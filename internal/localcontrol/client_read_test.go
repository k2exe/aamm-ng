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

func TestClientReadManagedAlert(t *testing.T) {
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

		if request.Operation != OperationRead {
			serverErr <- errors.New(
				"unexpected operation",
			)
			return
		}

		if request.Target != "all" {
			serverErr <- errors.New(
				"unexpected target",
			)
			return
		}

		_, err = io.WriteString(
			connection,
			`{"version":1,"ok":true,"result":`+
				`{"target":"all","kind":"managed",`+
				`"message":"Net open","size":8}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.Read(
		context.Background(),
		"all",
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf(
			"test server: %v",
			err,
		)
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

	if result.Message != "Net open" {
		t.Fatalf(
			"Message = %q; want Net open",
			result.Message,
		)
	}
}

func TestClientReadCanRetrieveLegacySource(t *testing.T) {
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

		if request.Operation != OperationRead ||
			request.Target != "legacy" {
			serverErr <- errors.New(
				"unexpected read request",
			)
			return
		}

		_, err = io.WriteString(
			connection,
			`{"version":1,"ok":true,"result":`+
				`{"target":"legacy","kind":"legacy",`+
				`"legacy_source":"<b>Old alert</b>",`+
				`"size":16}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.Read(
		context.Background(),
		"legacy",
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf(
			"test server: %v",
			err,
		)
	}

	if result.LegacySource != "<b>Old alert</b>" {
		t.Fatalf(
			"LegacySource = %q; want legacy source",
			result.LegacySource,
		)
	}
}

func TestClientReadReturnsRemoteError(t *testing.T) {
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

		if _, err := DecodeRequest(
			line[:len(line)-1],
		); err != nil {
			serverErr <- err
			return
		}

		_, err = io.WriteString(
			connection,
			`{"version":1,"ok":false,"error":`+
				`{"code":"not_found","message":"not found"}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	_, err = client.Read(
		context.Background(),
		"missing",
	)

	if serverErr := <-serverErr; serverErr != nil {
		t.Fatalf(
			"test server: %v",
			serverErr,
		)
	}

	var remoteErr *RemoteError

	if !errors.As(err, &remoteErr) {
		t.Fatalf(
			"error = %v; want RemoteError",
			err,
		)
	}

	if remoteErr.Code != ErrorNotFound {
		t.Fatalf(
			"Code = %q; want %q",
			remoteErr.Code,
			ErrorNotFound,
		)
	}
}

func TestClientReadRejectsInvalidTargetBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Read(
		context.Background(),
		"../etc/passwd",
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}
