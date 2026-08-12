package appconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenManagerUsesDefaultsWhenConfigIsMissing(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	manager, err := OpenManager(path)
	if err != nil {
		t.Fatalf("OpenManager() error = %v", err)
	}

	if actual := manager.Current(); actual != Defaults() {
		t.Fatalf(
			"Current() = %#v; want %#v",
			actual,
			Defaults(),
		)
	}
}

func TestOpenManagerRejectsMalformedConfig(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	if err := os.WriteFile(
		path,
		[]byte("{"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	_, err := OpenManager(path)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf(
			"OpenManager() error = %v; want %v",
			err,
			ErrInvalidConfig,
		)
	}
}

func TestManagerReplacePersistsConfig(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	manager, err := OpenManager(path)
	if err != nil {
		t.Fatalf("OpenManager() error = %v", err)
	}

	if err := manager.Replace(Defaults()); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	actual, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if actual != Defaults() {
		t.Fatalf(
			"persisted config = %#v; want %#v",
			actual,
			Defaults(),
		)
	}
}

func TestManagerReplaceRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	manager, err := OpenManager(path)
	if err != nil {
		t.Fatalf("OpenManager() error = %v", err)
	}

	err = manager.Replace(
		Config{
			Version: CurrentVersion + 1,
		},
	)

	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf(
			"Replace() error = %v; want %v",
			err,
			ErrUnsupportedVersion,
		)
	}

	if actual := manager.Current(); actual != Defaults() {
		t.Fatalf(
			"Current() after rejected Replace() = %#v; want %#v",
			actual,
			Defaults(),
		)
	}

	if _, statErr := os.Stat(path); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"config file Stat() error = %v; want %v",
			statErr,
			os.ErrNotExist,
		)
	}
}

func TestManagerReplaceTracksCommittedSaveAfterError(t *testing.T) {
	manager := &Manager{
		path: "synthetic-config.json",
		current: Config{
			Version: 0,
		},
	}

	saveErr := errors.New(
		"synthetic post-commit persistence failure",
	)

	err := manager.replaceWithSave(
		Defaults(),
		func(
			_ string,
			_ Config,
		) (bool, error) {
			return true, saveErr
		},
	)

	if !errors.Is(err, saveErr) {
		t.Fatalf(
			"replaceWithSave() error = %v; want %v",
			err,
			saveErr,
		)
	}

	if actual := manager.Current(); actual != Defaults() {
		t.Fatalf(
			"Current() = %#v; want committed %#v",
			actual,
			Defaults(),
		)
	}
}

func TestManagerReplaceKeepsCurrentAfterUncommittedError(
	t *testing.T,
) {
	previous := Config{
		Version: 0,
	}

	manager := &Manager{
		path:    "synthetic-config.json",
		current: previous,
	}

	saveErr := errors.New(
		"synthetic pre-commit persistence failure",
	)

	err := manager.replaceWithSave(
		Defaults(),
		func(
			_ string,
			_ Config,
		) (bool, error) {
			return false, saveErr
		},
	)

	if !errors.Is(err, saveErr) {
		t.Fatalf(
			"replaceWithSave() error = %v; want %v",
			err,
			saveErr,
		)
	}

	if actual := manager.Current(); actual != previous {
		t.Fatalf(
			"Current() = %#v; want previous %#v",
			actual,
			previous,
		)
	}
}
