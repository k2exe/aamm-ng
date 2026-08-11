package arednhosts

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	defaultDirectory     = "/var/run/arednlink/hosts"
	defaultMaxFiles      = 128
	defaultMaxFileBytes  = 256 * 1024
	defaultMaxTotalBytes = 2 * 1024 * 1024
)

var (
	ErrRead         = errors.New("AREDN host record read failed")
	ErrDataTooLarge = errors.New("AREDN host data exceeds limit")
)

type reader struct {
	directory     string
	maxFiles      int
	maxFileBytes  int64
	maxTotalBytes int64
}

func ReadLocal() ([]string, error) {
	return defaultReader().read()
}

func defaultReader() reader {
	return reader{
		directory:     defaultDirectory,
		maxFiles:      defaultMaxFiles,
		maxFileBytes:  defaultMaxFileBytes,
		maxTotalBytes: defaultMaxTotalBytes,
	}
}

func (r reader) read() ([]string, error) {
	if r.directory == "" ||
		r.maxFiles <= 0 ||
		r.maxFileBytes <= 0 ||
		r.maxTotalBytes <= 0 {
		return nil, fmt.Errorf(
			"%w: invalid reader configuration",
			ErrRead,
		)
	}

	entries, err := os.ReadDir(r.directory)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: directory",
			ErrRead,
		)
	}

	records := make([]string, 0, len(entries))
	fileCount := 0
	var totalBytes int64

	for _, entry := range entries {
		path := filepath.Join(
			r.directory,
			entry.Name(),
		)

		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: stat",
				ErrRead,
			)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if !info.Mode().IsRegular() {
			continue
		}

		fileCount++
		if fileCount > r.maxFiles {
			return nil, ErrDataTooLarge
		}

		if info.Size() > r.maxFileBytes {
			return nil, ErrDataTooLarge
		}

		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: open",
				ErrRead,
			)
		}

		data, readErr := io.ReadAll(
			io.LimitReader(
				file,
				r.maxFileBytes+1,
			),
		)

		closeErr := file.Close()

		if readErr != nil {
			return nil, fmt.Errorf(
				"%w: read",
				ErrRead,
			)
		}

		if closeErr != nil {
			return nil, fmt.Errorf(
				"%w: close",
				ErrRead,
			)
		}

		if int64(len(data)) > r.maxFileBytes {
			return nil, ErrDataTooLarge
		}

		totalBytes += int64(len(data))
		if totalBytes > r.maxTotalBytes {
			return nil, ErrDataTooLarge
		}

		records = append(records, string(data))
	}

	return records, nil
}
