package arednnodes

import (
	"context"
	"errors"
	"fmt"

	"github.com/k2exe/aamm-ng/internal/arednhosts"
)

var ErrUnavailable = errors.New("AREDN local node discovery unavailable")

type Fetcher struct {
	readRecords func() ([]string, error)
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		readRecords: arednhosts.ReadLocal,
	}
}

func (f *Fetcher) LocalNodes(
	_ context.Context,
) ([]string, error) {
	if f == nil || f.readRecords == nil {
		return nil, ErrUnavailable
	}

	records, err := f.readRecords()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: read local host records",
			ErrUnavailable,
		)
	}

	return NodesFromHostRecords(records), nil
}
