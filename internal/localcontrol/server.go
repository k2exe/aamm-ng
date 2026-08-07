package localcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	ProductionSocketPath = "/run/aamm-ng/aamm-ng.sock"

	socketMode     = 0660
	runtimeDirMode = 0750
	ioTimeout      = 5 * time.Second
)

var (
	ErrUnsafeRuntimeDir = errors.New("unsafe control runtime directory")
	ErrSocketPathExists = errors.New("control socket path already exists")
	ErrSocketOwnership  = errors.New("control socket ownership mismatch")
)

func Serve(
	ctx context.Context,
	socketPath string,
	store Store,
) error {
	runtimeGID, err := validateRuntimeDir(socketPath)
	if err != nil {
		return err
	}

	if _, err := os.Lstat(socketPath); err == nil {
		return ErrSocketPathExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect control socket path: %w", err)
	}

	address := &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	}

	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return fmt.Errorf("listen on control socket: %w", err)
	}
	listener.SetUnlinkOnClose(true)

	defer listener.Close()

	if err := os.Chmod(socketPath, socketMode); err != nil {
		return fmt.Errorf("set control socket mode: %w", err)
	}

	if err := validateSocket(socketPath, runtimeGID); err != nil {
		return err
	}

	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()

	defer close(done)

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("accept control connection: %w", err)
		}

		handleConnection(connection, store)
	}
}

func handleConnection(
	connection *net.UnixConn,
	store Store,
) {
	defer connection.Close()

	if err := connection.SetReadDeadline(
		time.Now().Add(ioTimeout),
	); err != nil {
		return
	}

	requestData, err := readRequest(connection)

	var response Response

	if err != nil {
		response = responseForError(err)
	} else {
		request, decodeErr := DecodeRequest(requestData)
		if decodeErr != nil {
			response = responseForError(decodeErr)
		} else {
			response = Dispatch(store, request)
		}
	}

	_ = connection.SetReadDeadline(time.Time{})

	if err := connection.SetWriteDeadline(
		time.Now().Add(ioTimeout),
	); err != nil {
		return
	}

	encoder := json.NewEncoder(connection)
	_ = encoder.Encode(response)
}

func readRequest(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(
		reader,
		MaxRequestBytes+2,
	)

	buffered := bufio.NewReader(limited)

	line, err := buffered.ReadBytes('\n')

	if len(line) > MaxRequestBytes+1 {
		return nil, ErrRequestTooLarge
	}

	if err != nil {
		if errors.Is(err, io.EOF) {
			if len(line) > MaxRequestBytes {
				return nil, ErrRequestTooLarge
			}

			return nil, fmt.Errorf(
				"%w: newline terminator required",
				ErrInvalidRequest,
			)
		}

		return nil, fmt.Errorf(
			"%w: read request: %v",
			ErrInvalidRequest,
			err,
		)
	}

	line = line[:len(line)-1]

	if len(line) > MaxRequestBytes {
		return nil, ErrRequestTooLarge
	}

	return line, nil
}

func validateRuntimeDir(
	socketPath string,
) (uint32, error) {
	dirPath := filepath.Dir(socketPath)

	info, err := os.Lstat(dirPath)
	if err != nil {
		return 0, fmt.Errorf(
			"%w: inspect %s: %v",
			ErrUnsafeRuntimeDir,
			dirPath,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return 0, fmt.Errorf(
			"%w: %s is not a real directory",
			ErrUnsafeRuntimeDir,
			dirPath,
		)
	}

	mode := info.Mode()

	if mode.Perm() != runtimeDirMode ||
		mode&os.ModeSetgid == 0 ||
		mode&os.ModeSetuid != 0 ||
		mode&os.ModeSticky != 0 {
		return 0, fmt.Errorf(
			"%w: %s must have mode 2750",
			ErrUnsafeRuntimeDir,
			dirPath,
		)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf(
			"%w: cannot inspect ownership of %s",
			ErrUnsafeRuntimeDir,
			dirPath,
		)
	}

	if stat.Uid != uint32(os.Geteuid()) {
		return 0, fmt.Errorf(
			"%w: %s must be owned by the daemon user",
			ErrUnsafeRuntimeDir,
			dirPath,
		)
	}

	return stat.Gid, nil
}

func validateSocket(
	socketPath string,
	runtimeGID uint32,
) error {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf(
			"%w: inspect socket: %v",
			ErrSocketOwnership,
			err,
		)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf(
			"%w: path is not a Unix socket",
			ErrSocketOwnership,
		)
	}

	if info.Mode().Perm() != socketMode {
		return fmt.Errorf(
			"%w: socket must have mode 0660",
			ErrSocketOwnership,
		)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf(
			"%w: cannot inspect socket ownership",
			ErrSocketOwnership,
		)
	}

	if stat.Uid != uint32(os.Geteuid()) ||
		stat.Gid != runtimeGID {
		return fmt.Errorf(
			"%w: socket did not inherit runtime directory ownership",
			ErrSocketOwnership,
		)
	}

	return nil
}
