package arednsource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeResolveUsesLocalRouteAndHostData(t *testing.T) {
	hostDirectory := t.TempDir()

	writeTestHostFile(
		t,
		hostDirectory,
		"hosts-a",
		`##192.0.2.20##
192.0.2.20       TEST-NODE-B
198.51.100.17    lan.TEST-NODE-B.local.mesh
`,
	)

	routeCommand := writeTestRouteCommand(
		t,
		`198.51.100.16/28 via 192.0.2.20 dev test0 table 20
`,
	)

	resolver := testRuntimeResolver(
		hostDirectory,
		routeCommand,
	)

	got, err := resolver.resolve(
		context.Background(),
		"198.51.100.29",
	)
	if err != nil {
		t.Fatal(err)
	}

	want := Attribution{
		SourceNode: "TEST-NODE-B",
	}

	if got != want {
		t.Fatalf(
			"attribution = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestRuntimeResolveReturnsAdvertisedHost(t *testing.T) {
	hostDirectory := t.TempDir()

	writeTestHostFile(
		t,
		hostDirectory,
		"hosts-a",
		`##192.0.2.20##
192.0.2.20       TEST-NODE-B
198.51.100.19    test-workstation
198.51.100.17    lan.TEST-NODE-B.local.mesh
`,
	)

	routeCommand := writeTestRouteCommand(
		t,
		`198.51.100.16/28 via 192.0.2.20 dev test0 table 20
`,
	)

	resolver := testRuntimeResolver(
		hostDirectory,
		routeCommand,
	)

	got, err := resolver.resolve(
		context.Background(),
		"198.51.100.19",
	)
	if err != nil {
		t.Fatal(err)
	}

	want := Attribution{
		SourceNode: "TEST-NODE-B",
		SourceHost: "test-workstation",
	}

	if got != want {
		t.Fatalf(
			"attribution = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestRuntimeResolveRejectsInvalidSourceBeforeIO(t *testing.T) {
	resolver := runtimeResolver{
		routeCommand:  "/does/not/exist",
		hostDirectory: "/does/not/exist",
		routeTimeout:  time.Second,
	}

	_, err := resolver.resolve(
		context.Background(),
		"not-an-ip",
	)

	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf(
			"error = %v; want ErrInvalidSource",
			err,
		)
	}
}

func TestRuntimeMapsHostReaderFailure(t *testing.T) {
	routeCommand := writeTestRouteCommand(
		t,
		"",
	)

	resolver := testRuntimeResolver(
		filepath.Join(t.TempDir(), "missing"),
		routeCommand,
	)

	_, err := resolver.resolve(
		context.Background(),
		"192.0.2.50",
	)

	if !errors.Is(err, ErrHostRecords) {
		t.Fatalf(
			"error = %v; want ErrHostRecords",
			err,
		)
	}
}

func TestRuntimeRejectsOversizedRouteOutput(t *testing.T) {
	hostDirectory := t.TempDir()

	writeTestHostFile(
		t,
		hostDirectory,
		"hosts-a",
		`##192.0.2.20##
192.0.2.20 TEST-NODE-B
`,
	)

	routeCommand := writeTestRouteCommand(
		t,
		`198.51.100.16/28 via 192.0.2.20 dev test0
`,
	)

	resolver := testRuntimeResolver(
		hostDirectory,
		routeCommand,
	)
	resolver.maxRouteBytes = 8

	_, err := resolver.resolve(
		context.Background(),
		"198.51.100.29",
	)

	if !errors.Is(err, ErrDataTooLarge) {
		t.Fatalf(
			"error = %v; want ErrDataTooLarge",
			err,
		)
	}
}

func TestRuntimeRejectsOversizedHostFile(t *testing.T) {
	hostDirectory := t.TempDir()

	writeTestHostFile(
		t,
		hostDirectory,
		"hosts-a",
		strings.Repeat("x", 32),
	)

	routeCommand := writeTestRouteCommand(
		t,
		"",
	)

	resolver := testRuntimeResolver(
		hostDirectory,
		routeCommand,
	)
	resolver.maxHostFileBytes = 8

	_, err := resolver.resolve(
		context.Background(),
		"192.0.2.50",
	)

	if !errors.Is(err, ErrDataTooLarge) {
		t.Fatalf(
			"error = %v; want ErrDataTooLarge",
			err,
		)
	}
}

func TestRuntimeRejectsTooManyHostFiles(t *testing.T) {
	hostDirectory := t.TempDir()

	writeTestHostFile(
		t,
		hostDirectory,
		"hosts-a",
		"",
	)

	writeTestHostFile(
		t,
		hostDirectory,
		"hosts-b",
		"",
	)

	routeCommand := writeTestRouteCommand(
		t,
		"",
	)

	resolver := testRuntimeResolver(
		hostDirectory,
		routeCommand,
	)
	resolver.maxHostFiles = 1

	_, err := resolver.resolve(
		context.Background(),
		"192.0.2.50",
	)

	if !errors.Is(err, ErrDataTooLarge) {
		t.Fatalf(
			"error = %v; want ErrDataTooLarge",
			err,
		)
	}
}

func TestRuntimeRouteCommandTimesOut(t *testing.T) {
	hostDirectory := t.TempDir()

	writeTestHostFile(
		t,
		hostDirectory,
		"hosts-a",
		"",
	)

	routeCommand := writeTestCommand(
		t,
		"while :; do :; done\n",
	)

	resolver := testRuntimeResolver(
		hostDirectory,
		routeCommand,
	)
	resolver.routeTimeout = 25 * time.Millisecond

	start := time.Now()

	_, err := resolver.resolve(
		context.Background(),
		"192.0.2.50",
	)

	elapsed := time.Since(start)

	if !errors.Is(err, ErrRouteQuery) {
		t.Fatalf(
			"error = %v; want ErrRouteQuery",
			err,
		)
	}

	if elapsed > 500*time.Millisecond {
		t.Fatalf(
			"timeout took %s; want at most 500ms",
			elapsed,
		)
	}
}

func testRuntimeResolver(
	hostDirectory string,
	routeCommand string,
) runtimeResolver {
	return runtimeResolver{
		routeCommand:      routeCommand,
		hostDirectory:     hostDirectory,
		routeTimeout:      time.Second,
		maxRouteBytes:     64 * 1024,
		maxHostFiles:      16,
		maxHostFileBytes:  64 * 1024,
		maxHostTotalBytes: 256 * 1024,
	}
}

func writeTestHostFile(
	t *testing.T,
	directory string,
	name string,
	content string,
) {
	t.Helper()

	path := filepath.Join(
		directory,
		name,
	)

	if err := os.WriteFile(
		path,
		[]byte(content),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
}

func writeTestRouteCommand(
	t *testing.T,
	output string,
) string {
	t.Helper()

	script := "printf '%s' " + shellQuote(output) + "\n"

	return writeTestCommand(
		t,
		script,
	)
}

func writeTestCommand(
	t *testing.T,
	body string,
) string {
	t.Helper()

	path := filepath.Join(
		t.TempDir(),
		"test-command",
	)

	content := "#!/bin/sh\n" + body

	if err := os.WriteFile(
		path,
		[]byte(content),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	return path
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(
		value,
		"'",
		"'\"'\"'",
	) + "'"
}
