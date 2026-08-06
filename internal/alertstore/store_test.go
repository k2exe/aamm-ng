package alertstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func TestOpenRequiresExistingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")

	store, err := Open(path)
	if !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("Open() error = %v; want ErrInvalidRoot", err)
	}

	if store != nil {
		t.Fatal("Open() returned a store for a missing directory")
	}

	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Open() created or changed missing directory: %v", statErr)
	}
}

func TestOpenRejectsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts")

	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("Open() error = %v; want ErrInvalidRoot", err)
	}

	if store != nil {
		t.Fatal("Open() returned a store for a regular file")
	}
}

func TestOpenRejectsSymlink(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "real")
	link := filepath.Join(parent, "linked")

	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}

	store, err := Open(link)
	if !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("Open() error = %v; want ErrInvalidRoot", err)
	}

	if store != nil {
		t.Fatal("Open() returned a store for a symlink")
	}
}

func TestReadManagedAlert(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "K2EXE-HAP-RB")
	message := mustMessage(t, "Line one\nLine two")

	writeAlert(t, directory, target.Filename(), []byte(message.EscapedHTML()))

	store := mustOpen(t, directory)
	defer store.Close()

	entry, err := store.Read(target)
	if err != nil {
		t.Fatal(err)
	}

	if entry.Kind != KindManaged {
		t.Fatalf("Kind = %v; want KindManaged", entry.Kind)
	}

	if entry.Message.String() != message.String() {
		t.Fatalf("Message = %q; want %q", entry.Message.String(), message.String())
	}

	if entry.LegacyHTML != "" {
		t.Fatalf("LegacyHTML = %q; want empty", entry.LegacyHTML)
	}
}

func TestReadLegacyAlertWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "all")
	legacy := []byte(`<b>Emergency Net</b><script>alert("x")</script>`)

	writeAlert(t, directory, target.Filename(), legacy)

	store := mustOpen(t, directory)
	defer store.Close()

	entry, err := store.Read(target)
	if err != nil {
		t.Fatal(err)
	}

	if entry.Kind != KindLegacy {
		t.Fatalf("Kind = %v; want KindLegacy", entry.Kind)
	}

	if entry.LegacyHTML != string(legacy) {
		t.Fatalf("LegacyHTML = %q; want exact stored content", entry.LegacyHTML)
	}

	after, err := os.ReadFile(filepath.Join(directory, target.Filename()))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(after, legacy) {
		t.Fatal("legacy alert changed during inspection")
	}
}

func TestReadReportsOversizedLegacyAlert(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "weather")
	content := bytes.Repeat([]byte("x"), MaxLegacyBytes+1)

	writeAlert(t, directory, target.Filename(), content)

	store := mustOpen(t, directory)
	defer store.Close()

	entry, err := store.Read(target)
	if err != nil {
		t.Fatal(err)
	}

	if entry.Kind != KindOversized {
		t.Fatalf("Kind = %v; want KindOversized", entry.Kind)
	}

	if entry.Size != int64(len(content)) {
		t.Fatalf("Size = %d; want %d", entry.Size, len(content))
	}

	if entry.Message != (alertmessage.Message{}) {
		t.Fatal("oversized entry returned a message")
	}

	if entry.LegacyHTML != "" {
		t.Fatal("oversized entry returned legacy content")
	}
}

func TestReadRejectsAlertSymlink(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	target := mustTarget(t, "all")

	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(outside, filepath.Join(directory, target.Filename())); err != nil {
		t.Fatal(err)
	}

	store := mustOpen(t, directory)
	defer store.Close()

	_, err := store.Read(target)
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("Read() error = %v; want ErrUnsafeFile", err)
	}
}

func TestReadRejectsDirectory(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "all")

	if err := os.Mkdir(filepath.Join(directory, target.Filename()), 0o700); err != nil {
		t.Fatal(err)
	}

	store := mustOpen(t, directory)
	defer store.Close()

	_, err := store.Read(target)
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("Read() error = %v; want ErrUnsafeFile", err)
	}
}

func TestReadRejectsZeroTarget(t *testing.T) {
	store := mustOpen(t, t.TempDir())
	defer store.Close()

	_, err := store.Read(alerttarget.Target{})
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("Read() error = %v; want ErrInvalidTarget", err)
	}
}

func TestReadAfterClose(t *testing.T) {
	store := mustOpen(t, t.TempDir())

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := store.Read(mustTarget(t, "all"))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Read() error = %v; want ErrClosed", err)
	}
}

func mustOpen(t *testing.T, path string) *Store {
	t.Helper()

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	return store
}

func mustTarget(t *testing.T, value string) alerttarget.Target {
	t.Helper()

	target, err := alerttarget.Parse(value)
	if err != nil {
		t.Fatal(err)
	}

	return target
}

func mustMessage(t *testing.T, value string) alertmessage.Message {
	t.Helper()

	message, err := alertmessage.Parse(value)
	if err != nil {
		t.Fatal(err)
	}

	return message
}

func writeAlert(t *testing.T, directory, name string, content []byte) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
}
