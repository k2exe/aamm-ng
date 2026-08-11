package localcontrol

import (
	"bufio"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
)

func TestClientConvertSendsCanonicalRequest(t *testing.T) {
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

		if request.Operation != OperationConvert {
			serverErr <- errors.New(
				"unexpected operation",
			)
			return
		}

		if request.Target != "legacy" {
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
				`{"target":"legacy","kind":"managed",`+
				`"backup_name":"legacy.txt.20260807T010203Z.bak"}}`+
				"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.Convert(
		testMutationContext(),
		"LEGACY",
		"Line one\r\nLine two",
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

	if result.Target != "legacy" {
		t.Fatalf(
			"Target = %q; want legacy",
			result.Target,
		)
	}

	if result.Kind != "managed" {
		t.Fatalf(
			"Kind = %q; want managed",
			result.Kind,
		)
	}

	if result.BackupName == "" {
		t.Fatal("BackupName is empty")
	}
}

func TestClientConvertRejectsInvalidTargetBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Convert(
		testMutationContext(),
		"../legacy",
		"Converted message",
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestClientConvertRejectsInvalidMessageBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Convert(
		testMutationContext(),
		"legacy",
		"",
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestClientConvertReturnsRemoteConflict(t *testing.T) {
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
				`{"code":"managed_conflict",`+
				`"message":"alert is already managed"}}`+
				"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	_, err = client.Convert(
		testMutationContext(),
		"legacy",
		"Converted message",
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

	if remoteErr.Code != ErrorManagedConflict {
		t.Fatalf(
			"Code = %q; want %q",
			remoteErr.Code,
			ErrorManagedConflict,
		)
	}
}
