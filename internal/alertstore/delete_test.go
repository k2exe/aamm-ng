package alertstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func TestDeleteBacksUpAndRemovesAlerts(t *testing.T) {
	managed := mustMessage(t, "Managed alert")

	tests := []struct {
		name    string
		target  string
		content []byte
	}{
		{
			name:    "managed",
			target:  "all",
			content: []byte(managed.EscapedHTML()),
		},
		{
			name:    "legacy",
			target:  "legacy",
			content: []byte(`<strong>Legacy alert</strong>`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			alertRoot := t.TempDir()
			backupRoot := newBackupRoot(t)
			target := mustTarget(t, test.target)

			writeAlert(
				t,
				alertRoot,
				target.Filename(),
				test.content,
			)

			store, err := Open(Config{
				AlertRoot:  alertRoot,
				BackupRoot: backupRoot,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			result, err := store.Delete(target)
			if err != nil {
				t.Fatal(err)
			}

			if result.BackupName == "" {
				t.Fatal("Delete() returned an empty backup name")
			}

			if !strings.Contains(
				result.BackupName,
				"-"+target.String()+"-",
			) {
				t.Fatalf(
					"BackupName = %q; want target name",
					result.BackupName,
				)
			}

			backupPath := filepath.Join(
				backupRoot,
				result.BackupName,
			)

			backup, err := os.ReadFile(backupPath)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(backup, test.content) {
				t.Fatal("backup does not match deleted alert")
			}

			info, err := os.Stat(backupPath)
			if err != nil {
				t.Fatal(err)
			}

			if info.Mode().Perm() != 0o600 {
				t.Fatalf(
					"backup mode = %04o; want 0600",
					info.Mode().Perm(),
				)
			}

			_, err = os.Lstat(filepath.Join(
				alertRoot,
				target.Filename(),
			))
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf(
					"deleted alert still exists: %v",
					err,
				)
			}
		})
	}
}

func TestDeleteRejectsOversizedWithoutBackupOrMutation(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	target := mustTarget(t, "weather")
	oversized := bytes.Repeat([]byte("x"), MaxLegacyBytes+1)

	writeAlert(t, alertRoot, target.Filename(), oversized)

	store, err := Open(Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = store.Delete(target)
	if !errors.Is(err, ErrOversizedConflict) {
		t.Fatalf(
			"Delete() error = %v; want ErrOversizedConflict",
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
		t.Fatal("oversized alert changed after rejected deletion")
	}
}

func TestDeleteMissingAlertCreatesNoBackup(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)

	store, err := Open(Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = store.Delete(mustTarget(t, "missing"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"Delete() error = %v; want os.ErrNotExist",
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
}

func TestDeleteRejectsAlertSymlink(t *testing.T) {
	alertRoot := t.TempDir()
	backupRoot := newBackupRoot(t)
	target := mustTarget(t, "all")
	outside := filepath.Join(t.TempDir(), "outside.txt")

	if err := os.WriteFile(
		outside,
		[]byte("outside"),
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

	_, err = store.Delete(target)
	if !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf(
			"Delete() error = %v; want ErrUnsafeFile",
			err,
		)
	}

	outsideContent, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}

	if string(outsideContent) != "outside" {
		t.Fatal("symlink destination changed")
	}

	backups, err := os.ReadDir(backupRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(backups) != 0 {
		t.Fatal("deletion created a backup for a symlink")
	}
}

func TestDeleteRejectsZeroTarget(t *testing.T) {
	store := mustOpen(t, t.TempDir())
	defer store.Close()

	_, err := store.Delete(alerttarget.Target{})
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf(
			"Delete() error = %v; want ErrInvalidTarget",
			err,
		)
	}
}

func TestDeleteAfterClose(t *testing.T) {
	store := mustOpen(t, t.TempDir())

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := store.Delete(mustTarget(t, "all"))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf(
			"Delete() error = %v; want ErrClosed",
			err,
		)
	}
}
