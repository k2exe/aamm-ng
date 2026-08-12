package arednsource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"time"

	"github.com/k2exe/aamm-ng/internal/arednhosts"
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

	hostRecords, err := arednhosts.Read(
		arednhosts.Config{
			Directory:     r.hostDirectory,
			MaxFiles:      r.maxHostFiles,
			MaxFileBytes:  r.maxHostFileBytes,
			MaxTotalBytes: r.maxHostTotalBytes,
		},
	)
	if err != nil {
		if errors.Is(err, arednhosts.ErrDataTooLarge) {
			return Attribution{}, ErrDataTooLarge
		}

		return Attribution{}, fmt.Errorf(
			"%w: %v",
			ErrHostRecords,
			err,
		)
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
