package appconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	CurrentVersion = 1
	MaxConfigBytes = 64 * 1024
)

var (
	ErrInvalidConfig      = errors.New("invalid application configuration")
	ErrUnsupportedVersion = errors.New("unsupported application configuration version")
	ErrTooLarge           = errors.New("application configuration exceeds size limit")
)

type Config struct {
	Version int `json:"version"`
}

func Defaults() Config {
	return Config{
		Version: CurrentVersion,
	}
}

func (config Config) Validate() error {
	if config.Version != CurrentVersion {
		return fmt.Errorf(
			"%w: %d",
			ErrUnsupportedVersion,
			config.Version,
		)
	}

	return nil
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			directory := filepath.Dir(path)

			info, directoryErr := os.Stat(directory)
			if directoryErr != nil {
				return Config{}, fmt.Errorf(
					"open application configuration directory: %w",
					directoryErr,
				)
			}

			if !info.IsDir() {
				return Config{}, fmt.Errorf(
					"%w: configuration parent is not a directory",
					ErrInvalidConfig,
				)
			}

			return Defaults(), nil
		}

		return Config{}, fmt.Errorf(
			"open application configuration: %w",
			err,
		)
	}
	defer file.Close()

	data, err := io.ReadAll(
		io.LimitReader(file, MaxConfigBytes+1),
	)
	if err != nil {
		return Config{}, fmt.Errorf(
			"read application configuration: %w",
			err,
		)
	}

	if len(data) > MaxConfigBytes {
		return Config{}, ErrTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var config Config

	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf(
			"%w: %v",
			ErrInvalidConfig,
			err,
		)
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, fmt.Errorf(
				"%w: multiple JSON values",
				ErrInvalidConfig,
			)
		}

		return Config{}, fmt.Errorf(
			"%w: trailing data: %v",
			ErrInvalidConfig,
			err,
		)
	}

	if err := config.Validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}
