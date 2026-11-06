package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/k2exe/aamm-ng/internal/arednauth"
	"github.com/k2exe/aamm-ng/internal/arednnodes"
	"github.com/k2exe/aamm-ng/internal/cgibridge"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
	"github.com/k2exe/aamm-ng/internal/portal"
	"github.com/k2exe/aamm-ng/internal/webadmin"
)

// portalSettingsInterval is how often the portal checks the stored settings.
// A change made on the Settings page applies at once. This also recovers the
// portal after the daemon restarts.
const portalSettingsInterval = 30 * time.Second

// portalRuntime lets the administrator UI control the portal.
type portalRuntime struct {
	controller *portal.Controller
	sessions   *portal.Sessions
}

func (runtime portalRuntime) Apply(enabled bool, reach string) portal.Status {
	return runtime.controller.Apply(enabled, reach)
}

func (runtime portalRuntime) Status() portal.Status {
	return runtime.controller.Status()
}

func (runtime portalRuntime) RevokeUser(name string) int {
	return runtime.sessions.RevokeUser(name)
}

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

	portalHandler, err := portal.NewHandler(
		alerts,
		arednnodes.NewFetcher(),
		portal.Options{},
	)
	if err != nil {
		return fmt.Errorf(
			"startup: portal: %w",
			err,
		)
	}

	// The portal is off until the settings turn it on. Turning it off, or
	// changing who can connect, ends every portal session.
	controller := portal.NewController(
		portalHandler,
		portal.ControllerOptions{
			OnStop: portalHandler.Sessions().RevokeAll,
		},
	)

	portalContext, stopPortal := context.WithCancel(ctx)

	var portalDone sync.WaitGroup

	portalDone.Add(1)

	go func() {
		defer portalDone.Done()

		controller.Run(portalContext, alerts, portalSettingsInterval)
	}()

	// Deferred calls run last in, first out: stop the portal, then wait.
	// This also stops it when the web server fails by itself.
	defer portalDone.Wait()
	defer stopPortal()

	handler := webadmin.NewHandlerWithPortal(
		verifier,
		alerts,
		alerts,
		portalRuntime{
			controller: controller,
			sessions:   portalHandler.Sessions(),
		},
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
