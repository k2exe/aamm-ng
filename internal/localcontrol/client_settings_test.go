package localcontrol

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

func TestClientSettingsReadSendsRequest(t *testing.T) {
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

		if request.Operation != OperationSettingsRead {
			serverErr <- errors.New("unexpected operation")
			return
		}

		if request.Settings != nil {
			serverErr <- errors.New("settings_read sent settings")
			return
		}

		if request.Audit != nil {
			serverErr <- errors.New("settings_read sent audit")
			return
		}

		_, err = io.WriteString(
			connection,
			`{"version":2,"ok":true,"result":{"version":1}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.SettingsRead(
		context.Background(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("test server: %v", err)
	}

	if result.Version != appconfig.CurrentVersion {
		t.Fatalf(
			"Version = %d; want %d",
			result.Version,
			appconfig.CurrentVersion,
		)
	}
}

func TestClientSettingsReplaceSendsConfigAndAudit(t *testing.T) {
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

		if request.Operation != OperationSettingsReplace {
			serverErr <- errors.New("unexpected operation")
			return
		}

		if request.Settings == nil {
			serverErr <- errors.New("settings_replace omitted settings")
			return
		}

		if *request.Settings != appconfig.Defaults() {
			serverErr <- errors.New("unexpected settings payload")
			return
		}

		if err := validateTestRequestAudit(
			request,
			testRequiredMutationAudit(),
		); err != nil {
			serverErr <- err
			return
		}

		_, err = io.WriteString(
			connection,
			`{"version":2,"ok":true,"result":{"version":1}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	result, err := client.SettingsReplace(
		testMutationContext(),
		appconfig.Defaults(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("test server: %v", err)
	}

	if result.Version != appconfig.CurrentVersion {
		t.Fatalf(
			"Version = %d; want %d",
			result.Version,
			appconfig.CurrentVersion,
		)
	}
}

func TestClientSettingsReplaceRequiresAuthenticatedIdentity(
	t *testing.T,
) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	_, err := client.SettingsReplace(
		context.Background(),
		appconfig.Defaults(),
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestClientSettingsReplaceRejectsInvalidConfigBeforeConnecting(
	t *testing.T,
) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	config := appconfig.Config{
		Version: appconfig.CurrentVersion + 1,
	}

	_, err := client.SettingsReplace(
		testMutationContext(),
		config,
	)

	if !errors.Is(err, appconfig.ErrUnsupportedVersion) {
		t.Fatalf(
			"error = %v; want %v",
			err,
			appconfig.ErrUnsupportedVersion,
		)
	}
}

func TestClientSettingsReadRejectsUnsupportedResponseVersion(
	t *testing.T,
) {
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
			`{"version":2,"ok":true,"result":{"version":2}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	_, err = client.SettingsRead(context.Background())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("test server: %v", err)
	}
}

func TestClientSettingsReadRejectsUnknownResponseField(
	t *testing.T,
) {
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
			`{"version":2,"ok":true,"result":{"version":1,"unexpected":true}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	_, err = client.SettingsRead(context.Background())

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("test server: %v", err)
	}
}

func TestClientSettingsReplaceRejectsInvalidResponseConfig(
	t *testing.T,
) {
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
			`{"version":2,"ok":true,"result":{"version":2}}`+"\n",
		)

		serverErr <- err
	}()

	client := &Client{
		socketPath: socketPath,
	}

	_, err = client.SettingsReplace(
		testMutationContext(),
		appconfig.Defaults(),
	)

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("test server: %v", err)
	}
}

func TestDecodeSettingsResultPreservesDurabilityWarning(
	t *testing.T,
) {
	result, err := decodeSettingsResult(
		Failure(
			ErrorSettingsDurabilityUncertain,
			"application settings applied; durability is uncertain",
		),
	)

	if err == nil {
		t.Fatal("decodeSettingsResult() error = nil; want warning")
	}

	if result != (appconfig.Config{}) {
		t.Fatalf(
			"result = %#v; want zero config on warning",
			result,
		)
	}

	var remoteErr *RemoteError

	if !errors.As(err, &remoteErr) {
		t.Fatalf(
			"error type = %T; want *RemoteError",
			err,
		)
	}

	if remoteErr.Code != ErrorSettingsDurabilityUncertain {
		t.Fatalf(
			"remote error code = %q; want %q",
			remoteErr.Code,
			ErrorSettingsDurabilityUncertain,
		)
	}

	if remoteErr.Message !=
		"application settings applied; durability is uncertain" {
		t.Fatalf(
			"remote error message = %q; want durability warning",
			remoteErr.Message,
		)
	}

	if errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"durability warning was classified as invalid response: %v",
			err,
		)
	}
}
