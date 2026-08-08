package localcontrol

import (
	"errors"
	"os"

	"github.com/k2exe/aamm-ng/internal/alertstore"
)

const (
	ErrorInvalidRequest     = "invalid_request"
	ErrorUnsupportedVersion = "unsupported_version"
	ErrorUnknownOperation   = "unknown_operation"
	ErrorInvalidTarget      = "invalid_target"
	ErrorInvalidMessage     = "invalid_message"
	ErrorNotFound           = "not_found"
	ErrorAlreadyExists      = "already_exists"
	ErrorLegacyConflict     = "legacy_conflict"
	ErrorOversizedConflict  = "oversized_conflict"
	ErrorManagedConflict    = "managed_conflict"
	ErrorSourceChanged      = "source_changed"
	ErrorUnsafeFile         = "unsafe_file"
	ErrorStoreClosed        = "store_closed"
	ErrorInternal           = "internal_error"
)

type EntryResult struct {
	Target       string `json:"target"`
	Kind         string `json:"kind"`
	Message      string `json:"message,omitempty"`
	LegacySource string `json:"legacy_source,omitempty"`
	Size         int64  `json:"size"`
}

type IssueResult struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type ListResult struct {
	Entries []EntryResult `json:"entries"`
	Issues  []IssueResult `json:"issues"`
}

type CreateResult struct {
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type WriteResult struct {
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type ConvertResult struct {
	Target     string `json:"target"`
	Kind       string `json:"kind"`
	BackupName string `json:"backup_name"`
}

type DeleteResult struct {
	Target     string `json:"target"`
	BackupName string `json:"backup_name"`
}

func entryResult(entry alertstore.Entry) EntryResult {
	result := EntryResult{
		Target: entry.Target.String(),
		Kind:   kindName(entry.Kind),
		Size:   entry.Size,
	}

	switch entry.Kind {
	case alertstore.KindManaged:
		result.Message = entry.Message.String()

	case alertstore.KindLegacy:
		result.LegacySource = entry.LegacyHTML
	}

	return result
}

func issueResult(issue alertstore.Issue) IssueResult {
	return IssueResult{
		Name:    issue.Name,
		Kind:    issueKindName(issue.Kind),
		Message: issue.Err.Error(),
	}
}

func listingResult(listing alertstore.Listing) ListResult {
	result := ListResult{
		Entries: make([]EntryResult, 0, len(listing.Entries)),
		Issues:  make([]IssueResult, 0, len(listing.Issues)),
	}

	for _, entry := range listing.Entries {
		item := entryResult(entry)

		// Listing intentionally omits legacy source. Retrieving legacy
		// content requires an explicit read operation for that target.
		item.LegacySource = ""

		result.Entries = append(
			result.Entries,
			item,
		)
	}

	for _, issue := range listing.Issues {
		result.Issues = append(
			result.Issues,
			issueResult(issue),
		)
	}

	return result
}

func kindName(kind alertstore.Kind) string {
	switch kind {
	case alertstore.KindManaged:
		return "managed"

	case alertstore.KindLegacy:
		return "legacy"

	case alertstore.KindOversized:
		return "oversized"

	default:
		return "unknown"
	}
}

func issueKindName(kind alertstore.IssueKind) string {
	switch kind {
	case alertstore.IssueMalformedName:
		return "malformed_name"

	case alertstore.IssueUnsafeEntry:
		return "unsafe_entry"

	case alertstore.IssueInspectionFailed:
		return "inspection_failed"

	default:
		return "inspection_failed"
	}
}

func responseForError(err error) Response {
	switch {
	case errors.Is(err, ErrUnsupportedVersion):
		return Failure(ErrorUnsupportedVersion, err.Error())

	case errors.Is(err, ErrUnknownOperation):
		return Failure(ErrorUnknownOperation, err.Error())

	case errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrRequestTooLarge):
		return Failure(ErrorInvalidRequest, err.Error())

	case errors.Is(err, alertstore.ErrInvalidTarget):
		return Failure(ErrorInvalidTarget, err.Error())

	case errors.Is(err, alertstore.ErrInvalidMessage):
		return Failure(ErrorInvalidMessage, err.Error())

	case errors.Is(err, os.ErrNotExist):
		return Failure(ErrorNotFound, err.Error())

	case errors.Is(err, alertstore.ErrAlreadyExists):
		return Failure(ErrorAlreadyExists, err.Error())

	case errors.Is(err, alertstore.ErrLegacyConflict):
		return Failure(ErrorLegacyConflict, err.Error())

	case errors.Is(err, alertstore.ErrOversizedConflict):
		return Failure(ErrorOversizedConflict, err.Error())

	case errors.Is(err, alertstore.ErrManagedConflict):
		return Failure(ErrorManagedConflict, err.Error())

	case errors.Is(err, alertstore.ErrSourceChanged):
		return Failure(ErrorSourceChanged, err.Error())

	case errors.Is(err, alertstore.ErrUnsafeFile):
		return Failure(ErrorUnsafeFile, err.Error())

	case errors.Is(err, alertstore.ErrClosed):
		return Failure(ErrorStoreClosed, err.Error())

	default:
		return Failure(ErrorInternal, err.Error())
	}
}
