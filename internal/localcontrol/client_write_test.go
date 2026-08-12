package localcontrol

import (
	"bufio"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
)

func TestClientWriteSendsCanonicalRequest(t *testing.T) {
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

		if err := validateTestRequestAudit(
			request,
			testRequiredMutationAudit(),
		); err != nil {
			serverErr <- err
			return
		}

		if request.Operation != OperationWrite {
			serverErr <- errors.New(
				"unexpected operation",
			)
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
			`{"version":2,"ok":true,"result":`+
				`{"target":"all","kind":"managed"}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.Write(
		testMutationContext(),
		"ALL",
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

func TestClientWriteRejectsInvalidTargetBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Write(
		testMutationContext(),
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

func TestClientWriteRejectsInvalidMessageBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	tests := map[string]string{
		"empty":     "",
		"blank":     "   ",
		"control":   "bad\x00message",
		"too large": string(make([]byte, 4097)),
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := client.Write(
				testMutationContext(),
				"all",
				message,
			)

			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf(
					"error = %v; want ErrInvalidRequest",
					err,
				)
			}
		})
	}
}

func TestClientWriteReturnsRemoteConflict(t *testing.T) {
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
			`{"version":2,"ok":false,"error":`+
				`{"code":"legacy_conflict",`+
				`"message":"legacy alert requires conversion"}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	_, err = client.Write(
		testMutationContext(),
		"all",
		"Replacement",
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

	if remoteErr.Code != ErrorLegacyConflict {
		t.Fatalf(
			"Code = %q; want %q",
			remoteErr.Code,
			ErrorLegacyConflict,
		)
	}
}
