package alertstore

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

type IssueKind uint8

const (
	IssueMalformedName IssueKind = iota + 1
	IssueUnsafeEntry
	IssueInspectionFailed
)

type Issue struct {
	Name string
	Kind IssueKind
	Err  error
}

type Listing struct {
	Entries []Entry
	Issues  []Issue
}

func (s *Store) List() (Listing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.alertRoot == nil {
		return Listing{}, ErrClosed
	}

	directory, err := s.alertRoot.Open(".")
	if err != nil {
		return Listing{}, fmt.Errorf(
			"open alert directory: %w",
			err,
		)
	}

	directoryEntries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()

	if err := errors.Join(readErr, closeErr); err != nil {
		return Listing{}, fmt.Errorf(
			"read alert directory: %w",
			err,
		)
	}

	var listing Listing

	for _, directoryEntry := range directoryEntries {
		name := directoryEntry.Name()

		if !strings.HasSuffix(name, ".txt") {
			continue
		}

		targetName := strings.TrimSuffix(name, ".txt")

		target, err := alerttarget.Parse(targetName)
		if err != nil {
			listing.Issues = append(listing.Issues, Issue{
				Name: name,
				Kind: IssueMalformedName,
				Err: fmt.Errorf(
					"invalid alert filename %q: %w",
					name,
					err,
				),
			})

			continue
		}

		if target.Filename() != name {
			listing.Issues = append(listing.Issues, Issue{
				Name: name,
				Kind: IssueMalformedName,
				Err: fmt.Errorf(
					"non-canonical alert filename %q; expected %q",
					name,
					target.Filename(),
				),
			})

			continue
		}

		entry, err := readEntry(s.alertRoot, target)
		if err != nil {
			kind := IssueInspectionFailed

			if errors.Is(err, ErrUnsafeFile) {
				kind = IssueUnsafeEntry
			}

			listing.Issues = append(listing.Issues, Issue{
				Name: name,
				Kind: kind,
				Err:  err,
			})

			continue
		}

		listing.Entries = append(listing.Entries, entry)
	}

	slices.SortFunc(listing.Entries, func(a, b Entry) int {
		return strings.Compare(
			strings.ToLower(a.Target.String()),
			strings.ToLower(b.Target.String()),
		)
	})

	slices.SortFunc(listing.Issues, func(a, b Issue) int {
		lowerComparison := strings.Compare(
			strings.ToLower(a.Name),
			strings.ToLower(b.Name),
		)

		if lowerComparison != 0 {
			return lowerComparison
		}

		return strings.Compare(a.Name, b.Name)
	})

	return listing, nil
}
