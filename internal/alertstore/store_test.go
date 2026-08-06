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

	store, err := Open(Config{AlertRoot: path, BackupRoot: newBackupRoot(t)})
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

	store, err := Open(Config{AlertRoot: path, BackupRoot: newBackupRoot(t)})
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

	store, err := Open(Config{
		AlertRoot:  link,
		BackupRoot: newBackupRoot(t),
	})
	if !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("Open() error = %v; want ErrInvalidRoot", err)
	}

	if store != nil {
		t.Fatal("Open() returned a store for a symlink")
	}
}

func TestOpenRequiresExistingBackupDirectory(t *testing.T) {
	config := Config{
		AlertRoot:  t.TempDir(),
		BackupRoot: filepath.Join(t.TempDir(), "missing"),
	}

	store, err := Open(config)
	if !errors.Is(err, ErrInvalidBackupRoot) {
		t.Fatalf("Open() error = %v; want ErrInvalidBackupRoot", err)
	}

	if store != nil {
		t.Fatal("Open() returned a store with a missing backup directory")
	}
}

func TestOpenRejectsBackupSymlink(t *testing.T) {
	parent := t.TempDir()
	realDirectory := filepath.Join(parent, "real")
	link := filepath.Join(parent, "linked")

	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{
		AlertRoot:  t.TempDir(),
		BackupRoot: link,
	})
	if !errors.Is(err, ErrInvalidBackupRoot) {
		t.Fatalf("Open() error = %v; want ErrInvalidBackupRoot", err)
	}

	if store != nil {
		t.Fatal("Open() returned a store with a symlinked backup directory")
	}
}

func TestOpenRequiresPrivateBackupPermissions(t *testing.T) {
	backupRoot := filepath.Join(t.TempDir(), "backups")

	if err := os.Mkdir(backupRoot, 0o750); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{
		AlertRoot:  t.TempDir(),
		BackupRoot: backupRoot,
	})
	if !errors.Is(err, ErrInvalidBackupRoot) {
		t.Fatalf("Open() error = %v; want ErrInvalidBackupRoot", err)
	}

	if store != nil {
		t.Fatal("Open() returned a store with non-private backup permissions")
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

func TestWriteCreatesManagedAlert(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "K2EXE-HAP-RB")
	message := mustMessage(t, "Net open at 19:00\nUse <primary> channel")

	store := mustOpen(t, directory)
	defer store.Close()

	if err := store.Write(target, message); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(
		filepath.Join(directory, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != message.EscapedHTML() {
		t.Fatalf(
			"stored content = %q; want %q",
			string(data),
			message.EscapedHTML(),
		)
	}

	info, err := os.Stat(
		filepath.Join(directory, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o644 {
		t.Fatalf(
			"stored mode = %04o; want 0644",
			info.Mode().Perm(),
		)
	}

	entry, err := store.Read(target)
	if err != nil {
		t.Fatal(err)
	}

	if entry.Kind != KindManaged {
		t.Fatalf("Kind = %v; want KindManaged", entry.Kind)
	}

	if entry.Message.String() != message.String() {
		t.Fatalf(
			"Message = %q; want %q",
			entry.Message.String(),
			message.String(),
		)
	}
}

func TestWriteReplacesManagedAlert(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "all")
	oldMessage := mustMessage(t, "Old message")
	newMessage := mustMessage(t, "Replacement message")

	writeAlert(
		t,
		directory,
		target.Filename(),
		[]byte(oldMessage.EscapedHTML()),
	)

	store := mustOpen(t, directory)
	defer store.Close()

	if err := store.Write(target, newMessage); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(
		filepath.Join(directory, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != newMessage.EscapedHTML() {
		t.Fatalf(
			"stored content = %q; want %q",
			string(data),
			newMessage.EscapedHTML(),
		)
	}

	info, err := os.Stat(
		filepath.Join(directory, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o644 {
		t.Fatalf(
			"stored mode = %04o; want 0644",
			info.Mode().Perm(),
		)
	}
}

func TestWriteRejectsLegacyAlertWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "all")
	legacy := []byte(`<strong>Legacy alert</strong>`)
	message := mustMessage(t, "Managed replacement")

	writeAlert(t, directory, target.Filename(), legacy)

	store := mustOpen(t, directory)
	defer store.Close()

	err := store.Write(target, message)
	if !errors.Is(err, ErrLegacyConflict) {
		t.Fatalf(
			"Write() error = %v; want ErrLegacyConflict",
			err,
		)
	}

	after, readErr := os.ReadFile(
		filepath.Join(directory, target.Filename()),
	)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if !bytes.Equal(after, legacy) {
		t.Fatal("legacy alert changed after rejected write")
	}
}

func TestWriteRejectsOversizedAlertWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	target := mustTarget(t, "weather")
	oversized := bytes.Repeat([]byte("x"), MaxLegacyBytes+1)
	message := mustMessage(t, "Managed replacement")

	writeAlert(t, directory, target.Filename(), oversized)

	store := mustOpen(t, directory)
	defer store.Close()

	err := store.Write(target, message)
	if !errors.Is(err, ErrOversizedConflict) {
		t.Fatalf(
			"Write() error = %v; want ErrOversizedConflict",
			err,
		)
	}

	after, readErr := os.ReadFile(
		filepath.Join(directory, target.Filename()),
	)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if !bytes.Equal(after, oversized) {
		t.Fatal("oversized alert changed after rejected write")
	}
}

func TestWriteRejectsAlertSymlink(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	target := mustTarget(t, "all")
	message := mustMessage(t, "Managed replacement")

	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(
		outside,
		filepath.Join(directory, target.Filename()),
	); err != nil {
		t.Fatal(err)
	}

	store := mustOpen(t, directory)
	defer store.Close()

	err := store.Write(target, message)
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("Write() error = %v; want ErrUnsafeFile", err)
	}

	after, readErr := os.ReadFile(outside)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if string(after) != "outside" {
		t.Fatal("symlink destination changed after rejected write")
	}
}

func TestWriteRejectsZeroTarget(t *testing.T) {
	store := mustOpen(t, t.TempDir())
	defer store.Close()

	err := store.Write(
		alerttarget.Target{},
		mustMessage(t, "Message"),
	)
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf(
			"Write() error = %v; want ErrInvalidTarget",
			err,
		)
	}
}

func TestWriteRejectsZeroMessage(t *testing.T) {
	store := mustOpen(t, t.TempDir())
	defer store.Close()

	err := store.Write(
		mustTarget(t, "all"),
		alertmessage.Message{},
	)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf(
			"Write() error = %v; want ErrInvalidMessage",
			err,
		)
	}
}

func TestWriteAfterClose(t *testing.T) {
	store := mustOpen(t, t.TempDir())

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	err := store.Write(
		mustTarget(t, "all"),
		mustMessage(t, "Message"),
	)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Write() error = %v; want ErrClosed", err)
	}
}

func newBackupRoot(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "backups")

	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

func mustOpen(t *testing.T, path string) *Store {
	t.Helper()

	store, err := Open(Config{AlertRoot: path, BackupRoot: newBackupRoot(t)})
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
