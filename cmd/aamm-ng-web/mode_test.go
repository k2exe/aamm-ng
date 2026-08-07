package main

import (
	"errors"
	"testing"
)

func TestParseModeServer(t *testing.T) {
	mode, err := parseMode(nil)
	if err != nil {
		t.Fatal(err)
	}

	if mode != modeServer {
		t.Fatalf(
			"mode = %v; want server",
			mode,
		)
	}
}

func TestParseModeCGI(t *testing.T) {
	mode, err := parseMode(
		[]string{"--cgi"},
	)
	if err != nil {
		t.Fatal(err)
	}

	if mode != modeCGI {
		t.Fatalf(
			"mode = %v; want CGI",
			mode,
		)
	}
}

func TestParseModeRejectsUnknownArguments(t *testing.T) {
	tests := [][]string{
		{"--unknown"},
		{"--cgi", "extra"},
		{"extra"},
	}

	for _, args := range tests {
		_, err := parseMode(args)

		if !errors.Is(
			err,
			ErrInvalidArguments,
		) {
			t.Fatalf(
				"parseMode(%q) error = %v; want ErrInvalidArguments",
				args,
				err,
			)
		}
	}
}
