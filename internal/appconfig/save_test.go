package appconfig

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	expected := Defaults()

	if err := Save(path, expected); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	actual, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if actual != expected {
		t.Fatalf(
			"Load() = %#v; want %#v",
			actual,
			expected,
		)
	}
}

func TestSaveUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	if err := Save(path, Defaults()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	if permissions := info.Mode().Perm(); permissions != 0600 {
		t.Fatalf(
			"config permissions = %04o; want 0600",
			permissions,
		)
	}
}

func TestSaveReplacesExistingFile(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	if err := os.WriteFile(
		path,
		[]byte("invalid old data\n"),
		0644,
	); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := Save(path, Defaults()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if config != Defaults() {
		t.Fatalf(
			"Load() = %#v; want %#v",
			config,
			Defaults(),
		)
	}
}

func TestSaveRejectsInvalidConfigWithoutReplacing(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	original := []byte("{\"version\":1}\n")

	if err := os.WriteFile(
		path,
		original,
		0600,
	); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err := Save(
		path,
		Config{
			Version: CurrentVersion + 1,
		},
	)

	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf(
			"Save() error = %v; want %v",
			err,
			ErrUnsupportedVersion,
		)
	}

	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if !bytes.Equal(actual, original) {
		t.Fatalf(
			"config changed after rejected Save(): %q",
			actual,
		)
	}
}

func TestSaveLeavesNoTemporaryFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(
		directory,
		"config.json",
	)

	if err := Save(path, Defaults()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf(
			"directory contains %d entries; want 1",
			len(entries),
		)
	}

	if entries[0].Name() != "config.json" {
		t.Fatalf(
			"directory entry = %q; want config.json",
			entries[0].Name(),
		)
	}
}
