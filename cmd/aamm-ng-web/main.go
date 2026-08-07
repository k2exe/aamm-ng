package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/k2exe/aamm-ng/internal/arednauth"
	"github.com/k2exe/aamm-ng/internal/cgibridge"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
	"github.com/k2exe/aamm-ng/internal/webadmin"
)

type listenerFactory func() (net.Listener, error)

func main() {
	mode, err := parseMode(os.Args[1:])
	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"usage: aamm-ng-web [--cgi]",
		)
		os.Exit(2)
	}

	if mode == modeCGI {
		if err := cgibridge.Run(
			context.Background(),
			os.Stdin,
			os.Stdout,
			os.Getenv,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"aamm-ng-web CGI: %v\n",
				err,
			)
			os.Exit(1)
		}

		return
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := run(
		ctx,
		os.Stdout,
		webadmin.ListenProduction,
	); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"aamm-ng-web: %v\n",
			err,
		)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	stdout io.Writer,
	listen listenerFactory,
) error {
	listener, err := listen()
	if err != nil {
		return fmt.Errorf(
			"startup: %w",
			err,
		)
	}

	verifier := arednauth.NewVerifier()
	alerts := localcontrol.NewClient()

	handler := webadmin.NewHandler(
		verifier,
		alerts,
	)

	fmt.Fprintln(
		stdout,
		"AAMM-NG web started",
	)

	if err := webadmin.Serve(
		ctx,
		listener,
		handler,
	); err != nil {
		return fmt.Errorf(
			"web server: %w",
			err,
		)
	}

	fmt.Fprintln(
		stdout,
		"AAMM-NG web stopped",
	)

	return nil
}
