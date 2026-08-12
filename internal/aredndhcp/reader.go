package aredndhcp

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	defaultLeasePath     = "/tmp/dhcp.leases"
	defaultMaxLeaseBytes = 256 * 1024
)

var (
	ErrUnavailable  = errors.New("AREDN DHCP lease data unavailable")
	ErrDataTooLarge = errors.New("AREDN DHCP lease data exceeds limit")
)

type reader struct {
	path     string
	maxBytes int64
}

func defaultReader() reader {
	return reader{
		path:     defaultLeasePath,
		maxBytes: defaultMaxLeaseBytes,
	}
}

func (r reader) lookup(source string) (string, error) {
	if r.path == "" || r.maxBytes <= 0 {
		return "", ErrUnavailable
	}

	info, err := os.Lstat(r.path)
	if err != nil {
		return "", fmt.Errorf(
			"%w: stat lease file",
			ErrUnavailable,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return "", ErrUnavailable
	}

	if info.Size() > r.maxBytes {
		return "", ErrDataTooLarge
	}

	file, err := os.Open(r.path)
	if err != nil {
		return "", fmt.Errorf(
			"%w: open lease file",
			ErrUnavailable,
		)
	}

	openedInfo, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()

		return "", fmt.Errorf(
			"%w: verify lease file",
			ErrUnavailable,
		)
	}

	if !openedInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) {
		_ = file.Close()
		return "", ErrUnavailable
	}

	data, readErr := io.ReadAll(
		io.LimitReader(
			file,
			r.maxBytes+1,
		),
	)

	closeErr := file.Close()

	if readErr != nil {
		return "", fmt.Errorf(
			"%w: read lease file",
			ErrUnavailable,
		)
	}

	if closeErr != nil {
		return "", fmt.Errorf(
			"%w: close lease file",
			ErrUnavailable,
		)
	}

	if int64(len(data)) > r.maxBytes {
		return "", ErrDataTooLarge
	}

	return Lookup(
		string(data),
		source,
	)
}

func LookupLocal(source string) (string, error) {
	return defaultReader().lookup(source)
}
