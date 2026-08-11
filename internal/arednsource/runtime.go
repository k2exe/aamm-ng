package arednsource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	defaultRouteCommand  = "/sbin/ip"
	defaultHostDirectory = "/var/run/arednlink/hosts"
	defaultRouteTimeout  = 2 * time.Second
	defaultMaxRouteBytes = 1024 * 1024
	defaultMaxHostFiles  = 128
	defaultMaxHostFile   = 256 * 1024
	defaultMaxHostTotal  = 2 * 1024 * 1024
)

var (
	ErrRouteQuery   = errors.New("AREDN route query failed")
	ErrHostRecords  = errors.New("AREDN host record read failed")
	ErrDataTooLarge = errors.New("AREDN source data exceeds limit")
)

type runtimeResolver struct {
	routeCommand      string
	hostDirectory     string
	routeTimeout      time.Duration
	maxRouteBytes     int64
	maxHostFiles      int
	maxHostFileBytes  int64
	maxHostTotalBytes int64
}

func ResolveLocal(
	ctx context.Context,
	source string,
) (Attribution, error) {
	return defaultRuntimeResolver().resolve(ctx, source)
}

func defaultRuntimeResolver() runtimeResolver {
	return runtimeResolver{
		routeCommand:      defaultRouteCommand,
		hostDirectory:     defaultHostDirectory,
		routeTimeout:      defaultRouteTimeout,
		maxRouteBytes:     defaultMaxRouteBytes,
		maxHostFiles:      defaultMaxHostFiles,
		maxHostFileBytes:  defaultMaxHostFile,
		maxHostTotalBytes: defaultMaxHostTotal,
	}
}

func (r runtimeResolver) resolve(
	ctx context.Context,
	source string,
) (Attribution, error) {
	address, err := netip.ParseAddr(source)
	if err != nil {
		return Attribution{}, ErrInvalidSource
	}

	if !address.Unmap().Is4() {
		return Attribution{}, ErrInvalidSource
	}

	hostRecords, err := r.readHostRecords()
	if err != nil {
		return Attribution{}, err
	}

	routeOutput, err := r.readRoutes(ctx)
	if err != nil {
		return Attribution{}, err
	}

	return Resolve(
		address.Unmap().String(),
		routeOutput,
		hostRecords,
	)
}

func (r runtimeResolver) readRoutes(
	ctx context.Context,
) (string, error) {
	routeContext, cancel := context.WithTimeout(
		ctx,
		r.routeTimeout,
	)
	defer cancel()

	command := exec.CommandContext(
		routeContext,
		r.routeCommand,
		"-4",
		"route",
		"show",
		"table",
		"all",
	)

	command.Stderr = io.Discard

	stdout, err := command.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("%w: stdout pipe", ErrRouteQuery)
	}

	if err := command.Start(); err != nil {
		return "", fmt.Errorf("%w: start", ErrRouteQuery)
	}

	output, readErr := io.ReadAll(
		io.LimitReader(
			stdout,
			r.maxRouteBytes+1,
		),
	)

	if int64(len(output)) > r.maxRouteBytes {
		_ = command.Process.Kill()
		_ = command.Wait()

		return "", ErrDataTooLarge
	}

	waitErr := command.Wait()

	if routeContext.Err() != nil {
		return "", fmt.Errorf(
			"%w: %w",
			ErrRouteQuery,
			routeContext.Err(),
		)
	}

	if readErr != nil {
		return "", fmt.Errorf("%w: read", ErrRouteQuery)
	}

	if waitErr != nil {
		return "", fmt.Errorf("%w: command", ErrRouteQuery)
	}

	return string(output), nil
}

func (r runtimeResolver) readHostRecords() ([]string, error) {
	entries, err := os.ReadDir(r.hostDirectory)
	if err != nil {
		return nil, fmt.Errorf("%w: directory", ErrHostRecords)
	}

	records := make([]string, 0, len(entries))
	fileCount := 0
	var totalBytes int64

	for _, entry := range entries {
		path := filepath.Join(
			r.hostDirectory,
			entry.Name(),
		)

		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("%w: stat", ErrHostRecords)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if !info.Mode().IsRegular() {
			continue
		}

		fileCount++
		if fileCount > r.maxHostFiles {
			return nil, ErrDataTooLarge
		}

		if info.Size() > r.maxHostFileBytes {
			return nil, ErrDataTooLarge
		}

		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%w: open", ErrHostRecords)
		}

		data, readErr := io.ReadAll(
			io.LimitReader(
				file,
				r.maxHostFileBytes+1,
			),
		)

		closeErr := file.Close()

		if readErr != nil {
			return nil, fmt.Errorf("%w: read", ErrHostRecords)
		}

		if closeErr != nil {
			return nil, fmt.Errorf("%w: close", ErrHostRecords)
		}

		if int64(len(data)) > r.maxHostFileBytes {
			return nil, ErrDataTooLarge
		}

		totalBytes += int64(len(data))
		if totalBytes > r.maxHostTotalBytes {
			return nil, ErrDataTooLarge
		}

		records = append(records, string(data))
	}

	return records, nil
}
