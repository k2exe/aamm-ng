package main

import (
	"errors"
)

type commandMode uint8

const (
	modeServer commandMode = iota
	modeCGI
)

var ErrInvalidArguments = errors.New(
	"invalid command arguments",
)

func parseMode(args []string) (commandMode, error) {
	switch {
	case len(args) == 0:
		return modeServer, nil

	case len(args) == 1 &&
		args[0] == "--cgi":
		return modeCGI, nil

	default:
		return modeServer, ErrInvalidArguments
	}
}
