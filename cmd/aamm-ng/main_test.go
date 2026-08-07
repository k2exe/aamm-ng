package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/alertstore"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

func TestParseConfigRequiresAlertRoot(t *testing.T) {
	_, err := parseConfig(
		[]string{
			"--backup-root",
			"/tmp/backups",
		},
		io.Discard,
	)

	if err == nil ||
		!strings.Contains(err.Error(), "--alert-root is required") {
		t.Fatalf(
			"parseConfig() error = %v; want required alert root",
			err,
		)
	}
}

func TestParseConfigRequiresBackupRoot(t *testing.T) {
	_, err := parseConfig(
		[]string{
			"--alert-root",
			"/tmp/alerts",
		},
		io.Discard,
	)

	if err == nil ||
		!strings.Contains(err.Error(), "--backup-root is required") {
		t.Fatalf(
			"parseConfig() error = %v; want required backup root",
			err,
		)
	}
}

func TestParseConfigAcceptsRequiredRoots(t *testing.T) {
	config, err := parseConfig(
		[]string{
			"--alert-root",
			"/alerts",
			"--backup-root",
			"/backups",
		},
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	if config.alertRoot != "/alerts" {
		t.Fatalf(
			"alertRoot = %q; want /alerts",
			config.alertRoot,
		)
	}

	if config.backupRoot != "/backups" {
		t.Fatalf(
			"backupRoot = %q; want /backups",
			config.backupRoot,
		)
	}
}

func TestRunFailsWhenAlertRootIsMissing(t *testing.T) {
	backupRoot := newBackupRoot(t)
	missing := filepath.Join(t.TempDir(), "missing")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := run(
		ctx,
		[]string{
			"--alert-root",
			missing,
			"--backup-root",
			backupRoot,
		},
		io.Discard,
		io.Discard,
	)

	if !errors.Is(err, alertstore.ErrInvalidRoot) {
		t.Fatalf(
			"run() error = %v; want ErrInvalidRoot",
			err,
		)
	}
}

func TestRunFailsWhenBackupRootIsUnsafe(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := filepath.Join(t.TempDir(), "backups")

	if err := os.Mkdir(backupRoot, 0o750); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := run(
		ctx,
		[]string{
			"--alert-root",
			alertRoot,
			"--backup-root",
			backupRoot,
		},
		io.Discard,
		io.Discard,
	)

	if !errors.Is(err, alertstore.ErrInvalidBackupRoot) {
		t.Fatalf(
			"run() error = %v; want ErrInvalidBackupRoot",
			err,
		)
	}
}

func TestRunFailsWhenControlRuntimeDirIsUnsafe(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)

	runtimeDir := t.TempDir()

	if err := os.Chmod(runtimeDir, 0o750); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(runtimeDir, "aamm-ng.sock")

	err := runWithSocketPath(
		context.Background(),
		[]string{
			"--alert-root",
			alertRoot,
			"--backup-root",
			backupRoot,
		},
		io.Discard,
		io.Discard,
		socketPath,
	)

	if !errors.Is(err, localcontrol.ErrUnsafeRuntimeDir) {
		t.Fatalf(
			"runWithSocketPath() error = %v; want ErrUnsafeRuntimeDir",
			err,
		)
	}
}

func TestRunStaysIdleUntilContextCancellation(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	socketPath := newControlSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	stdout := &startWriter{
		started: started,
	}

	done := make(chan error, 1)

	go func() {
		done <- runWithSocketPath(
			ctx,
			[]string{
				"--alert-root",
				alertRoot,
				"--backup-root",
				backupRoot,
			},
			stdout,
			io.Discard,
			socketPath,
		)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("service did not report successful startup")
	}

	select {
	case err := <-done:
		t.Fatalf(
			"service exited before cancellation: %v",
			err,
		)
	default:
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() error = %v; want nil", err)
		}

	case <-time.After(time.Second):
		t.Fatal("service did not stop after cancellation")
	}

	if !strings.Contains(
		stdout.String(),
		"AAMM-NG stopped",
	) {
		t.Fatalf(
			"stdout = %q; want shutdown message",
			stdout.String(),
		)
	}
}

type startWriter struct {
	mu      sync.Mutex
	once    sync.Once
	started chan struct{}
	buffer  bytes.Buffer
}

func (writer *startWriter) Write(value []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()

	written, err := writer.buffer.Write(value)

	if bytes.Contains(value, []byte("AAMM-NG started")) {
		writer.once.Do(func() {
			close(writer.started)
		})
	}

	return written, err
}

func (writer *startWriter) String() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()

	return writer.buffer.String()
}

func newControlSocketPath(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}

	return filepath.Join(dir, "aamm-ng.sock")
}

func newBackupRoot(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "backups")

	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}
