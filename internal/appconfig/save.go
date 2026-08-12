package appconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func Save(path string, config Config) error {
	_, err := save(path, config)
	return err
}

func save(
	path string,
	config Config,
) (bool, error) {
	return saveWithDirectorySync(
		path,
		config,
		func(directory *os.File) error {
			return directory.Sync()
		},
	)
}

func saveWithDirectorySync(
	path string,
	config Config,
	syncDirectory func(*os.File) error,
) (bool, error) {
	if err := config.Validate(); err != nil {
		return false, err
	}

	data, err := json.Marshal(config)
	if err != nil {
		return false, fmt.Errorf(
			"%w: encode: %v",
			ErrInvalidConfig,
			err,
		)
	}

	data = append(data, '\n')

	if len(data) > MaxConfigBytes {
		return false, ErrTooLarge
	}

	directory := filepath.Dir(path)
	base := filepath.Base(path)

	temp, err := os.CreateTemp(
		directory,
		"."+base+".tmp-*",
	)
	if err != nil {
		return false, fmt.Errorf(
			"create temporary application configuration: %w",
			err,
		)
	}

	tempPath := temp.Name()
	renamed := false

	defer func() {
		if !renamed {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(0600); err != nil {
		return false, fmt.Errorf(
			"set application configuration permissions: %w",
			err,
		)
	}

	if _, err := temp.Write(data); err != nil {
		return false, fmt.Errorf(
			"write application configuration: %w",
			err,
		)
	}

	if err := temp.Sync(); err != nil {
		return false, fmt.Errorf(
			"sync application configuration: %w",
			err,
		)
	}

	if err := temp.Close(); err != nil {
		return false, fmt.Errorf(
			"close application configuration: %w",
			err,
		)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return false, fmt.Errorf(
			"replace application configuration: %w",
			err,
		)
	}

	renamed = true

	directoryHandle, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf(
			"%w: open application configuration directory: %w",
			ErrDurabilityUncertain,
			err,
		)
	}
	defer directoryHandle.Close()

	if err := syncDirectory(directoryHandle); err != nil {
		return true, fmt.Errorf(
			"%w: sync application configuration directory: %w",
			ErrDurabilityUncertain,
			err,
		)
	}

	return true, nil
}
