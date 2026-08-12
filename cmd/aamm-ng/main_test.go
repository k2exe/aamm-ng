package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/alertstore"
	"github.com/k2exe/aamm-ng/internal/appconfig"
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
			"--config-path",
			"/settings/config.json",
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
	configPath := newConfigPath(t)
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
			"--config-path",
			configPath,
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
	configPath := newConfigPath(t)

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
			"--config-path",
			configPath,
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
	configPath := newConfigPath(t)

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
			"--config-path",
			configPath,
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
	configPath := newConfigPath(t)
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
				"--config-path",
				configPath,
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

func newConfigPath(t *testing.T) string {
	t.Helper()

	directory := filepath.Join(
		t.TempDir(),
		"settings",
	)

	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	return filepath.Join(
		directory,
		"config.json",
	)
}

func newBackupRoot(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "backups")

	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestParseConfigRequiresConfigPath(t *testing.T) {
	_, err := parseConfig(
		[]string{
			"--alert-root",
			"/alerts",
			"--backup-root",
			"/backups",
		},
		io.Discard,
	)

	if err == nil ||
		!strings.Contains(err.Error(), "--config-path is required") {
		t.Fatalf(
			"parseConfig() error = %v; want required config path",
			err,
		)
	}
}

func TestParseConfigAcceptsConfigPath(t *testing.T) {
	config, err := parseConfig(
		[]string{
			"--alert-root",
			"/alerts",
			"--backup-root",
			"/backups",
			"--config-path",
			"/settings/config.json",
		},
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	if config.configPath != "/settings/config.json" {
		t.Fatalf(
			"configPath = %q; want /settings/config.json",
			config.configPath,
		)
	}
}

func TestRunFailsWhenConfigDirectoryIsMissing(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	configPath := filepath.Join(
		t.TempDir(),
		"settings",
		"config.json",
	)
	socketPath := newControlSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runWithSocketPath(
		ctx,
		[]string{
			"--alert-root",
			alertRoot,
			"--backup-root",
			backupRoot,
			"--config-path",
			configPath,
		},
		io.Discard,
		io.Discard,
		socketPath,
	)

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"runWithSocketPath() error = %v; want %v",
			err,
			os.ErrNotExist,
		)
	}
}

func TestRunFailsWhenConfigIsMalformed(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	configPath := newConfigPath(t)
	socketPath := newControlSocketPath(t)

	if err := os.WriteFile(
		configPath,
		[]byte("{"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runWithSocketPath(
		ctx,
		[]string{
			"--alert-root",
			alertRoot,
			"--backup-root",
			backupRoot,
			"--config-path",
			configPath,
		},
		io.Discard,
		io.Discard,
		socketPath,
	)

	if !errors.Is(err, appconfig.ErrInvalidConfig) {
		t.Fatalf(
			"runWithSocketPath() error = %v; want %v",
			err,
			appconfig.ErrInvalidConfig,
		)
	}
}

func TestRunServesAndPersistsApplicationSettings(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	configPath := newConfigPath(t)
	socketPath := newControlSocketPath(t)

	ctx, cancel := context.WithCancel(context.Background())

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
				"--config-path",
				configPath,
			},
			stdout,
			io.Discard,
			socketPath,
		)
	}()

	defer func() {
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf(
					"runWithSocketPath() shutdown error = %v",
					err,
				)
			}

		case <-time.After(time.Second):
			t.Error("service did not stop after cancellation")
		}
	}()

	select {
	case <-started:
	case err := <-done:
		t.Fatalf(
			"service exited before startup: %v",
			err,
		)
	case <-time.After(time.Second):
		t.Fatal("service did not report successful startup")
	}

	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"config file exists before replacement: %v",
			err,
		)
	}

	readResponse := daemonControlRoundTrip(
		t,
		socketPath,
		`{"version":2,"operation":"settings_read"}`,
	)

	if !readResponse.OK {
		t.Fatalf(
			"settings_read response = %#v; want success",
			readResponse,
		)
	}

	replacementResponse := daemonControlRoundTrip(
		t,
		socketPath,
		`{"version":2,"operation":"settings_replace","settings":{"version":1},"audit":{"auth_node":"TEST-NODE-A","auth_role":"admin","source_ip":"192.0.2.44"}}`,
	)

	if !replacementResponse.OK {
		t.Fatalf(
			"settings_replace response = %#v; want success",
			replacementResponse,
		)
	}

	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf(
			"persisted config file: %v",
			err,
		)
	}

	loaded, err := appconfig.Load(configPath)
	if err != nil {
		t.Fatalf(
			"load persisted config: %v",
			err,
		)
	}

	if loaded.Version != appconfig.CurrentVersion {
		t.Fatalf(
			"persisted config version = %d; want %d",
			loaded.Version,
			appconfig.CurrentVersion,
		)
	}
}

func daemonControlRoundTrip(
	t *testing.T,
	socketPath string,
	request string,
) localcontrol.Response {
	t.Helper()

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(
		time.Now().Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}

	if _, err := connection.Write(
		append([]byte(request), '\n'),
	); err != nil {
		t.Fatal(err)
	}

	var response localcontrol.Response

	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		t.Fatal(err)
	}

	return response
}
