package localcontrol

import (
	"bufio"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
)

func TestClientDeleteSendsCanonicalRequest(t *testing.T) {
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

		if request.Operation != OperationDelete {
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

		if request.Message != "" {
			serverErr <- errors.New(
				"delete unexpectedly sent message",
			)
			return
		}

		_, err = io.WriteString(
			connection,
			`{"version":2,"ok":true,"result":`+
				`{"target":"all",`+
				`"backup_name":"all.txt.20260807T010203Z.bak"}}`+
				"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.Delete(
		testMutationContext(),
		"ALL",
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

	if result.BackupName == "" {
		t.Fatal("BackupName is empty")
	}
}

func TestClientDeleteRejectsInvalidTargetBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Delete(
		testMutationContext(),
		"../all",
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestClientDeleteReturnsRemoteNotFound(t *testing.T) {
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
				`{"code":"not_found",`+
				`"message":"alert not found"}}`+
				"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	_, err = client.Delete(
		testMutationContext(),
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
