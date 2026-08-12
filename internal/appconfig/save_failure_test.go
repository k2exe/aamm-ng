package appconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveInvalidConfigCreatesNothing(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(
		directory,
		"config.json",
	)

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

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf(
			"directory contains %d entries after rejected Save(); want 0",
			len(entries),
		)
	}
}

func TestSaveMissingDirectoryFailsWithoutCreatingIt(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(
		root,
		"settings",
	)
	path := filepath.Join(
		directory,
		"config.json",
	)

	err := Save(path, Defaults())
	if err == nil {
		t.Fatal("Save() error = nil; want failure")
	}

	if _, statErr := os.Stat(directory); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"settings directory Stat() error = %v; want %v",
			statErr,
			os.ErrNotExist,
		)
	}

	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatalf("ReadDir() error = %v", readErr)
	}

	if len(entries) != 0 {
		t.Fatalf(
			"root contains %d entries after failed Save(); want 0",
			len(entries),
		)
	}
}

func TestSaveReportsCommittedAfterDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	syncErr := errors.New(
		"synthetic directory sync failure",
	)

	committed, err := saveWithDirectorySync(
		path,
		Defaults(),
		func(_ *os.File) error {
			return syncErr
		},
	)

	if !committed {
		t.Fatal(
			"saveWithDirectorySync() committed = false; want true",
		)
	}

	if !errors.Is(err, syncErr) {
		t.Fatalf(
			"saveWithDirectorySync() error = %v; want %v",
			err,
			syncErr,
		)
	}

	actual, loadErr := Load(path)
	if loadErr != nil {
		t.Fatalf(
			"Load() after committed sync failure: %v",
			loadErr,
		)
	}

	if actual != Defaults() {
		t.Fatalf(
			"persisted config = %#v; want %#v",
			actual,
			Defaults(),
		)
	}
}

func TestSaveReportsUncommittedBeforeRename(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(
		root,
		"missing",
		"config.json",
	)

	committed, err := saveWithDirectorySync(
		path,
		Defaults(),
		func(_ *os.File) error {
			return nil
		},
	)

	if committed {
		t.Fatal(
			"saveWithDirectorySync() committed = true; want false",
		)
	}

	if err == nil {
		t.Fatal(
			"saveWithDirectorySync() error = nil; want failure",
		)
	}
}

func TestSaveClassifiesCommittedDirectorySyncFailure(
	t *testing.T,
) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	syncErr := errors.New(
		"synthetic directory sync failure",
	)

	committed, err := saveWithDirectorySync(
		path,
		Defaults(),
		func(_ *os.File) error {
			return syncErr
		},
	)

	if !committed {
		t.Fatal(
			"saveWithDirectorySync() committed = false; want true",
		)
	}

	if !errors.Is(err, ErrDurabilityUncertain) {
		t.Fatalf(
			"saveWithDirectorySync() error = %v; want ErrDurabilityUncertain",
			err,
		)
	}

	if !errors.Is(err, syncErr) {
		t.Fatalf(
			"saveWithDirectorySync() error = %v; want underlying sync error",
			err,
		)
	}
}
