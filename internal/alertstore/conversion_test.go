package alertstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func TestConvertLegacyBacksUpAndReplacesAlert(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	target := mustTarget(t, "all")
	legacy := []byte(`<strong>Legacy alert</strong>`)
	message := mustMessage(t, "Managed replacement")

	writeAlert(t, alertRoot, target.Filename(), legacy)

	store, err := Open(Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	result, err := store.ConvertLegacy(target, message)
	if err != nil {
		t.Fatal(err)
	}

	if result.BackupName == "" {
		t.Fatal("ConvertLegacy() returned an empty backup name")
	}

	if !strings.Contains(result.BackupName, "-all-") {
		t.Fatalf(
			"BackupName = %q; want target name",
			result.BackupName,
		)
	}

	backupPath := filepath.Join(backupRoot, result.BackupName)

	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(backup, legacy) {
		t.Fatal("backup does not match original legacy alert")
	}

	backupInfo, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}

	if backupInfo.Mode().Perm() != 0o600 {
		t.Fatalf(
			"backup mode = %04o; want 0600",
			backupInfo.Mode().Perm(),
		)
	}

	active, err := os.ReadFile(
		filepath.Join(alertRoot, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(active) != message.EscapedHTML() {
		t.Fatalf(
			"active alert = %q; want %q",
			string(active),
			message.EscapedHTML(),
		)
	}

	activeInfo, err := os.Stat(
		filepath.Join(alertRoot, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if activeInfo.Mode().Perm() != 0o644 {
		t.Fatalf(
			"active mode = %04o; want 0644",
			activeInfo.Mode().Perm(),
		)
	}

	entry, err := store.Read(target)
	if err != nil {
		t.Fatal(err)
	}

	if entry.Kind != KindManaged {
		t.Fatalf("Kind = %v; want KindManaged", entry.Kind)
	}
}

func TestConvertRejectsOversizedWithoutBackupOrMutation(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	target := mustTarget(t, "weather")
	oversized := bytes.Repeat([]byte("x"), MaxLegacyBytes+1)
	message := mustMessage(t, "Weather alert replaced")

	writeAlert(t, alertRoot, target.Filename(), oversized)

	store, err := Open(Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = store.ConvertLegacy(target, message)
	if !errors.Is(err, ErrOversizedConflict) {
		t.Fatalf(
			"ConvertLegacy() error = %v; want ErrOversizedConflict",
			err,
		)
	}

	backups, err := os.ReadDir(backupRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(backups) != 0 {
		t.Fatalf(
			"backup directory contains %d files; want none",
			len(backups),
		)
	}

	after, err := os.ReadFile(
		filepath.Join(alertRoot, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(after, oversized) {
		t.Fatal("oversized alert changed after rejected conversion")
	}
}

func TestBackupRetentionKeepsJustCreatedBackup(t *testing.T) {
	const retentionLimit = 16

	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)

	// Deliberately give all existing backups timestamps that sort
	// later than the backup this test will create. Retention must
	// protect the just-created rollback copy rather than blindly
	// deleting the lexicographically oldest filename.
	for i := 0; i < retentionLimit; i++ {
		name := fmt.Sprintf(
			"99991231T235959.%09dZ-seed-%016x.txt",
			i,
			i+1,
		)

		if err := os.WriteFile(
			filepath.Join(backupRoot, name),
			[]byte("seed backup"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}

	target := mustTarget(t, "all")
	legacy := []byte("<strong>Legacy alert</strong>")
	message := mustMessage(t, "Managed replacement")

	writeAlert(t, alertRoot, target.Filename(), legacy)

	store, err := Open(Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	result, err := store.ConvertLegacy(target, message)
	if err != nil {
		t.Fatal(err)
	}

	backups, err := os.ReadDir(backupRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(backups) != retentionLimit {
		t.Fatalf(
			"backup count = %d; want %d",
			len(backups),
			retentionLimit,
		)
	}

	if _, err := os.Stat(
		filepath.Join(backupRoot, result.BackupName),
	); err != nil {
		t.Fatalf(
			"just-created backup %q was not retained: %v",
			result.BackupName,
			err,
		)
	}
}

func TestConvertRejectsManagedAlertWithoutBackup(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	target := mustTarget(t, "all")
	current := mustMessage(t, "Current managed alert")
	replacement := mustMessage(t, "Replacement")

	writeAlert(
		t,
		alertRoot,
		target.Filename(),
		[]byte(current.EscapedHTML()),
	)

	store, err := Open(Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = store.ConvertLegacy(target, replacement)
	if !errors.Is(err, ErrManagedConflict) {
		t.Fatalf(
			"ConvertLegacy() error = %v; want ErrManagedConflict",
			err,
		)
	}

	backups, err := os.ReadDir(backupRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(backups) != 0 {
		t.Fatalf(
			"backup directory contains %d files; want none",
			len(backups),
		)
	}

	active, err := os.ReadFile(
		filepath.Join(alertRoot, target.Filename()),
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(active) != current.EscapedHTML() {
		t.Fatal("managed alert changed after rejected conversion")
	}
}

func TestConvertRejectsAlertSymlink(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	target := mustTarget(t, "all")
	outside := filepath.Join(t.TempDir(), "outside.txt")

	if err := os.WriteFile(
		outside,
		[]byte("<b>outside</b>"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(
		outside,
		filepath.Join(alertRoot, target.Filename()),
	); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = store.ConvertLegacy(
		target,
		mustMessage(t, "Replacement"),
	)
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf(
			"ConvertLegacy() error = %v; want ErrUnsafeFile",
			err,
		)
	}

	backups, err := os.ReadDir(backupRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(backups) != 0 {
		t.Fatal("conversion created a backup for a symlink")
	}
}

func TestConvertRejectsZeroTarget(t *testing.T) {
	store := mustOpen(t, t.TempDir())
	defer store.Close()

	_, err := store.ConvertLegacy(
		alerttarget.Target{},
		mustMessage(t, "Replacement"),
	)
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf(
			"ConvertLegacy() error = %v; want ErrInvalidTarget",
			err,
		)
	}
}

func TestConvertRejectsZeroMessage(t *testing.T) {
	store := mustOpen(t, t.TempDir())
	defer store.Close()

	_, err := store.ConvertLegacy(
		mustTarget(t, "all"),
		alertmessage.Message{},
	)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf(
			"ConvertLegacy() error = %v; want ErrInvalidMessage",
			err,
		)
	}
}

func TestConvertAfterClose(t *testing.T) {
	store := mustOpen(t, t.TempDir())

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := store.ConvertLegacy(
		mustTarget(t, "all"),
		mustMessage(t, "Replacement"),
	)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf(
			"ConvertLegacy() error = %v; want ErrClosed",
			err,
		)
	}
}
