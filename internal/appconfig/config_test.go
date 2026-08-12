package appconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	config := Defaults()

	if config.Version != CurrentVersion {
		t.Fatalf(
			"Defaults().Version = %d; want %d",
			config.Version,
			CurrentVersion,
		)
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Defaults().Validate() error = %v", err)
	}
}

func TestValidateRejectsUnsupportedVersion(t *testing.T) {
	tests := []int{
		0,
		CurrentVersion + 1,
	}

	for _, version := range tests {
		config := Config{
			Version: version,
		}

		err := config.Validate()
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf(
				"Validate() version %d error = %v; want %v",
				version,
				err,
				ErrUnsupportedVersion,
			)
		}
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	expected := Defaults()

	if config != expected {
		t.Fatalf(
			"Load() = %#v; want %#v",
			config,
			expected,
		)
	}
}

func TestLoadValidConfig(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	data := []byte("{\"version\":1}\n")

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if config.Version != CurrentVersion {
		t.Fatalf(
			"Load().Version = %d; want %d",
			config.Version,
			CurrentVersion,
		)
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	if err := os.WriteFile(
		path,
		[]byte("{"),
		0600,
	); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf(
			"Load() error = %v; want %v",
			err,
			ErrInvalidConfig,
		)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	data := []byte(
		"{\"version\":1,\"unexpected\":true}\n",
	)

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf(
			"Load() error = %v; want %v",
			err,
			ErrInvalidConfig,
		)
	}
}

func TestLoadRejectsFutureVersion(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	data := []byte("{\"version\":2}\n")

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf(
			"Load() error = %v; want %v",
			err,
			ErrUnsupportedVersion,
		)
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(
		t.TempDir(),
		"config.json",
	)

	data := strings.Repeat("x", MaxConfigBytes+1)

	if err := os.WriteFile(
		path,
		[]byte(data),
		0600,
	); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf(
			"Load() error = %v; want %v",
			err,
			ErrTooLarge,
		)
	}
}

func TestLoadMissingDirectoryFails(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(
		root,
		"settings",
		"config.json",
	)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil; want storage failure")
	}

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"Load() error = %v; want %v",
			err,
			os.ErrNotExist,
		)
	}
}
