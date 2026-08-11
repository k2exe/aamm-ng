package localcontrol

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientCallSuccess(t *testing.T) {
	response, err := callAgainstResponse(
		t,
		`{"version":2,"ok":true,"result":{"entries":[],"issues":[]}}`+"\n",
	)

	if err != nil {
		t.Fatal(err)
	}

	if !response.OK {
		t.Fatal("response OK = false; want true")
	}

	if response.Version != ProtocolVersion {
		t.Fatalf(
			"version = %d; want %d",
			response.Version,
			ProtocolVersion,
		)
	}

	if response.Error != nil {
		t.Fatalf(
			"error = %#v; want nil",
			response.Error,
		)
	}
}

func TestClientReturnsRemoteFailure(t *testing.T) {
	response, err := callAgainstResponse(
		t,
		`{"version":2,"ok":false,"error":{"code":"not_found","message":"not found"}}`+"\n",
	)

	if err != nil {
		t.Fatal(err)
	}

	if response.OK {
		t.Fatal("response OK = true; want false")
	}

	if response.Error == nil {
		t.Fatal("response error = nil")
	}

	if response.Error.Code != ErrorNotFound {
		t.Fatalf(
			"error code = %q; want %q",
			response.Error.Code,
			ErrorNotFound,
		)
	}
}

func TestClientRejectsInvalidRequestBeforeConnecting(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Call(
		context.Background(),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationList,
			Target:    "all",
		},
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestClientRejectsOversizedResponse(t *testing.T) {
	_, err := callAgainstResponse(
		t,
		strings.Repeat("x", MaxResponseBytes+1)+"\n",
	)

	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf(
			"error = %v; want ErrResponseTooLarge",
			err,
		)
	}
}

func TestClientRequiresResponseNewline(t *testing.T) {
	_, err := callAgainstResponse(
		t,
		`{"version":2,"ok":true}`,
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}
}

func TestClientRejectsMalformedResponses(t *testing.T) {
	tests := map[string]string{
		"malformed JSON": "not-json\n",
		"wrong version":  `{"version":1,"ok":true}` + "\n",
		"missing error":  `{"version":2,"ok":false}` + "\n",
		"error on success": `{"version":2,"ok":true,"error":` +
			`{"code":"internal_error","message":"bad"}}` + "\n",
		"result on failure": `{"version":2,"ok":false,"result":{},` +
			`"error":{"code":"internal_error","message":"bad"}}` + "\n",
		"multiple values": `{"version":2,"ok":true} {"version":2,"ok":true}` + "\n",
	}

	for name, wireResponse := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := callAgainstResponse(
				t,
				wireResponse,
			)

			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf(
					"error = %v; want ErrInvalidResponse",
					err,
				)
			}
		})
	}
}

func TestClientReportsUnavailableSocket(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.Call(
		context.Background(),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationList,
		},
	)

	if !errors.Is(err, ErrControlUnavailable) {
		t.Fatalf(
			"error = %v; want ErrControlUnavailable",
			err,
		)
	}
}

func TestClientHonorsContextCancellation(t *testing.T) {
	socketPath := filepath.Join(
		t.TempDir(),
		"control.sock",
	)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requestReceived := make(chan struct{})
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)

		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()

		_, err = bufio.NewReader(connection).ReadBytes('\n')
		if err != nil {
			return
		}

		close(requestReceived)

		_, _ = io.Copy(
			io.Discard,
			connection,
		)
	}()

	client := &Client{
		socketPath: socketPath,
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	result := make(chan error, 1)

	go func() {
		_, err := client.Call(
			ctx,
			Request{
				Version:   ProtocolVersion,
				Operation: OperationList,
			},
		)

		result <- err
	}()

	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}

	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"error = %v; want context.Canceled",
				err,
			)
		}

	case <-time.After(time.Second):
		t.Fatal("client did not stop after cancellation")
	}

	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server connection did not close")
	}
}

func callAgainstResponse(
	t *testing.T,
	wireResponse string,
) (Response, error) {
	t.Helper()

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

		if len(line) == 0 || line[len(line)-1] != '\n' {
			serverErr <- errors.New(
				"request missing newline",
			)
			return
		}

		request, err := DecodeRequest(
			line[:len(line)-1],
		)
		if err != nil {
			serverErr <- err
			return
		}

		if request.Operation != OperationList {
			serverErr <- errors.New(
				"unexpected operation",
			)
			return
		}

		_, err = io.WriteString(
			connection,
			wireResponse,
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	response, callErr := client.Call(
		context.Background(),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationList,
		},
	)

	if err := <-serverErr; err != nil {
		t.Fatalf(
			"test server: %v",
			err,
		)
	}

	return response, callErr
}
