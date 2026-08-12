package localcontrol

import (
	"context"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

func TestServeWithSettingsReadRoundTrip(t *testing.T) {
	socketPath := testSocketPath(t)

	settings := &fakeSettingsStore{
		current: appconfig.Defaults(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServeWithSettings(
			ctx,
			socketPath,
			&fakeStore{},
			settings,
			ready,
		)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf(
			"ServeWithSettings() exited before ready: %v",
			err,
		)
	case <-time.After(time.Second):
		t.Fatal("ServeWithSettings() did not become ready")
	}

	response := controlRoundTrip(
		t,
		socketPath,
		`{"version":2,"operation":"settings_read"}`,
	)

	result := resultObject(t, response)

	if result["version"] != float64(appconfig.CurrentVersion) {
		t.Fatalf(
			"settings version = %#v; want %d",
			result["version"],
			appconfig.CurrentVersion,
		)
	}

	if settings.currentCalls != 1 {
		t.Fatalf(
			"Current calls = %d; want 1",
			settings.currentCalls,
		)
	}

	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("ServeWithSettings() error = %v", err)
	}
}

func TestServeWithSettingsReplaceRoundTrip(t *testing.T) {
	socketPath := testSocketPath(t)

	settings := &fakeSettingsStore{
		current: appconfig.Defaults(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServeWithSettings(
			ctx,
			socketPath,
			&fakeStore{},
			settings,
			ready,
		)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf(
			"ServeWithSettings() exited before ready: %v",
			err,
		)
	case <-time.After(time.Second):
		t.Fatal("ServeWithSettings() did not become ready")
	}

	response := controlRoundTrip(
		t,
		socketPath,
		`{"version":2,"operation":"settings_replace","settings":{"version":1},"audit":{"auth_node":"TEST-NODE-A","auth_role":"admin","source_ip":"192.0.2.44"}}`,
	)

	result := resultObject(t, response)

	if result["version"] != float64(appconfig.CurrentVersion) {
		t.Fatalf(
			"settings version = %#v; want %d",
			result["version"],
			appconfig.CurrentVersion,
		)
	}

	if settings.replaceCalls != 1 {
		t.Fatalf(
			"Replace calls = %d; want 1",
			settings.replaceCalls,
		)
	}

	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("ServeWithSettings() error = %v", err)
	}
}

func TestServeWithSettingsPreservesAlertDispatch(t *testing.T) {
	socketPath := testSocketPath(t)

	settings := &fakeSettingsStore{
		current: appconfig.Defaults(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- ServeWithSettings(
			ctx,
			socketPath,
			&fakeStore{},
			settings,
			ready,
		)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf(
			"ServeWithSettings() exited before ready: %v",
			err,
		)
	case <-time.After(time.Second):
		t.Fatal("ServeWithSettings() did not become ready")
	}

	response := controlRoundTrip(
		t,
		socketPath,
		`{"version":2,"operation":"list"}`,
	)

	if !response.OK {
		t.Fatalf(
			"alert response = %#v; want success",
			response,
		)
	}

	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("ServeWithSettings() error = %v", err)
	}
}
