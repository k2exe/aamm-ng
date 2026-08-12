package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/k2exe/aamm-ng/internal/alertstore"
	"github.com/k2exe/aamm-ng/internal/appconfig"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

type config struct {
	alertRoot  string
	backupRoot string
	configPath string
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := run(
		ctx,
		os.Args[1:],
		os.Stdout,
		os.Stderr,
	); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintf(os.Stderr, "aamm-ng: %v\n", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) error {
	return runWithSocketPath(
		ctx,
		args,
		stdout,
		stderr,
		localcontrol.ProductionSocketPath,
	)
}

func runWithSocketPath(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	socketPath string,
) error {
	config, err := parseConfig(args, stderr)
	if err != nil {
		return err
	}

	settings, err := appconfig.OpenManager(config.configPath)
	if err != nil {
		return fmt.Errorf(
			"startup: application configuration: %w",
			err,
		)
	}

	store, err := alertstore.Open(alertstore.Config{
		AlertRoot:  config.alertRoot,
		BackupRoot: config.backupRoot,
	})
	if err != nil {
		return fmt.Errorf("startup: %w", err)
	}

	ready := make(chan struct{})
	serverErr := make(chan error, 1)

	go func() {
		serverErr <- localcontrol.ServeWithSettings(
			ctx,
			socketPath,
			store,
			settings,
			ready,
		)
	}()

	select {
	case <-ready:
	case err := <-serverErr:
		startupErr := fmt.Errorf(
			"startup: local control: %w",
			err,
		)

		if closeErr := store.Close(); closeErr != nil {
			return errors.Join(
				startupErr,
				fmt.Errorf(
					"shutdown: close alert store: %w",
					closeErr,
				),
			)
		}

		return startupErr
	}

	fmt.Fprintln(stdout, "AAMM-NG started")

	if err := <-serverErr; err != nil {
		serverFailure := fmt.Errorf(
			"local control: %w",
			err,
		)

		if closeErr := store.Close(); closeErr != nil {
			return errors.Join(
				serverFailure,
				fmt.Errorf(
					"shutdown: close alert store: %w",
					closeErr,
				),
			)
		}

		return serverFailure
	}

	if err := store.Close(); err != nil {
		return fmt.Errorf("shutdown: close alert store: %w", err)
	}

	fmt.Fprintln(stdout, "AAMM-NG stopped")

	return nil
}

func parseConfig(
	args []string,
	stderr io.Writer,
) (config, error) {
	var config config

	flags := flag.NewFlagSet("aamm-ng", flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.StringVar(
		&config.alertRoot,
		"alert-root",
		"",
		"path to the alert directory",
	)

	flags.StringVar(
		&config.backupRoot,
		"backup-root",
		"",
		"path to the backup directory",
	)

	flags.StringVar(
		&config.configPath,
		"config-path",
		"",
		"path to the application configuration file",
	)

	if err := flags.Parse(args); err != nil {
		return config, err
	}

	if config.alertRoot == "" {
		return config, errors.New("--alert-root is required")
	}

	if config.backupRoot == "" {
		return config, errors.New("--backup-root is required")
	}

	if config.configPath == "" {
		return config, errors.New("--config-path is required")
	}

	if flags.NArg() != 0 {
		return config, fmt.Errorf(
			"unexpected argument %q",
			flags.Arg(0),
		)
	}

	return config, nil
}
