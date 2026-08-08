package localcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeListRoundTrip(t *testing.T) {
	socketPath := testSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			&fakeStore{},
			nil,
		)
	}()

	waitForSocket(t, socketPath)

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	_, err = connection.Write(
		[]byte(`{"version":1,"operation":"list"}` + "\n"),
	)
	if err != nil {
		t.Fatal(err)
	}

	var response Response

	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}

	if !response.OK {
		t.Fatalf("response = %#v; want success", response)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop")
	}
}

func TestServeCreatesSocketMode0660(t *testing.T) {
	socketPath := testSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			&fakeStore{},
			nil,
		)
	}()

	waitForSocket(t, socketPath)

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}

	if got := info.Mode().Perm(); got != 0660 {
		t.Fatalf("socket mode = %04o; want 0660", got)
	}

	cancel()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestServeRejectsRuntimeDirWithoutSetgid(t *testing.T) {
	dir := t.TempDir()

	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}

	err := Serve(
		context.Background(),
		filepath.Join(dir, "aamm-ng.sock"),
		&fakeStore{},
		nil,
	)

	if !errors.Is(err, ErrUnsafeRuntimeDir) {
		t.Fatalf(
			"Serve() error = %v; want ErrUnsafeRuntimeDir",
			err,
		)
	}
}

func TestServeDoesNotRemoveExistingPath(t *testing.T) {
	socketPath := testSocketPath(t)

	if err := os.WriteFile(
		socketPath,
		[]byte("do not remove"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	err := Serve(
		context.Background(),
		socketPath,
		&fakeStore{},
		nil,
	)

	if !errors.Is(err, ErrSocketPathExists) {
		t.Fatalf(
			"Serve() error = %v; want ErrSocketPathExists",
			err,
		)
	}

	content, err := os.ReadFile(socketPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != "do not remove" {
		t.Fatal("existing path was modified")
	}
}

func TestServeRemovesStaleSocket(t *testing.T) {
	socketPath := testSocketPath(t)

	staleListener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{
			Name: socketPath,
			Net:  "unix",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	staleListener.SetUnlinkOnClose(false)

	if err := staleListener.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("stale path is not a Unix socket")
	}

	ctx, cancel := context.WithCancel(context.Background())

	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			&fakeStore{},
			ready,
		)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf(
			"Serve() exited before recovering stale socket: %v",
			err,
		)
	case <-time.After(time.Second):
		t.Fatal("Serve() did not recover stale socket")
	}

	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestServeDoesNotRemoveActiveSocket(t *testing.T) {
	socketPath := testSocketPath(t)

	activeListener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{
			Name: socketPath,
			Net:  "unix",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer activeListener.Close()

	err = Serve(
		context.Background(),
		socketPath,
		&fakeStore{},
		nil,
	)

	if !errors.Is(err, ErrSocketPathExists) {
		t.Fatalf(
			"Serve() error = %v; want ErrSocketPathExists",
			err,
		)
	}

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf(
			"active socket was removed: %v",
			err,
		)
	}

	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("active socket path was replaced")
	}
}

func TestServeRejectsRequestWithoutNewline(t *testing.T) {
	socketPath := testSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			&fakeStore{},
			nil,
		)
	}()

	waitForSocket(t, socketPath)

	connection, err := net.DialUnix(
		"unix",
		nil,
		&net.UnixAddr{
			Name: socketPath,
			Net:  "unix",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = connection.Write(
		[]byte(`{"version":1,"operation":"list"}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	var response Response

	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}

	connection.Close()

	requireErrorCode(
		t,
		response,
		ErrorInvalidRequest,
	)

	cancel()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestServeRejectsOversizedRequest(t *testing.T) {
	socketPath := testSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			&fakeStore{},
			nil,
		)
	}()

	waitForSocket(t, socketPath)

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	request := strings.Repeat(
		"x",
		MaxRequestBytes+1,
	) + "\n"

	if _, err := connection.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(connection)

	var response Response

	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		t.Fatal(err)
	}

	connection.Close()

	requireErrorCode(
		t,
		response,
		ErrorInvalidRequest,
	)

	cancel()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestServeRemovesSocketOnCleanShutdown(t *testing.T) {
	socketPath := testSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			&fakeStore{},
			nil,
		)
	}()

	waitForSocket(t, socketPath)

	cancel()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(socketPath); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"socket still exists after shutdown: %v",
			err,
		)
	}
}

func TestServeSignalsReadyAfterSocketSetup(t *testing.T) {
	socketPath := testSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- Serve(
			ctx,
			socketPath,
			&fakeStore{},
			ready,
		)
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("Serve() did not signal readiness")
	}

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("ready signaled before Unix socket existed")
	}

	if got := info.Mode().Perm(); got != 0660 {
		t.Fatalf(
			"socket mode = %04o after readiness; want 0660",
			got,
		)
	}

	cancel()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func testSocketPath(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	if err := os.Chmod(dir, 0750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}

	return filepath.Join(dir, "aamm-ng.sock")
}

func waitForSocket(
	t *testing.T,
	socketPath string,
) {
	t.Helper()

	deadline := time.Now().Add(time.Second)

	for time.Now().Before(deadline) {
		info, err := os.Lstat(socketPath)

		if err == nil &&
			info.Mode()&os.ModeSocket != 0 {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf(
		"socket %s was not created",
		socketPath,
	)
}
