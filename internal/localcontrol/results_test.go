package localcontrol

import (
	"errors"
	"os"
	"testing"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alertstore"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func TestEntryResultManaged(t *testing.T) {
	target, err := alerttarget.Parse("all")
	if err != nil {
		t.Fatal(err)
	}

	message, err := alertmessage.Parse("Net open")
	if err != nil {
		t.Fatal(err)
	}

	result := entryResult(alertstore.Entry{
		Target:  target,
		Kind:    alertstore.KindManaged,
		Message: message,
		Size:    8,
	})

	if result.Target != "all" {
		t.Fatalf("Target = %q; want all", result.Target)
	}

	if result.Kind != "managed" {
		t.Fatalf("Kind = %q; want managed", result.Kind)
	}

	if result.Message != "Net open" {
		t.Fatalf(
			"Message = %q; want Net open",
			result.Message,
		)
	}

	if result.LegacySource != "" {
		t.Fatalf(
			"LegacySource = %q; want empty",
			result.LegacySource,
		)
	}
}

func TestEntryResultLegacyUsesSourceField(t *testing.T) {
	target, err := alerttarget.Parse("legacy")
	if err != nil {
		t.Fatal(err)
	}

	const source = `<strong>Legacy</strong>`

	result := entryResult(alertstore.Entry{
		Target:     target,
		Kind:       alertstore.KindLegacy,
		LegacyHTML: source,
		Size:       int64(len(source)),
	})

	if result.Kind != "legacy" {
		t.Fatalf("Kind = %q; want legacy", result.Kind)
	}

	if result.LegacySource != source {
		t.Fatalf(
			"LegacySource = %q; want %q",
			result.LegacySource,
			source,
		)
	}

	if result.Message != "" {
		t.Fatalf(
			"Message = %q; want empty",
			result.Message,
		)
	}
}

func TestEntryResultOversizedDoesNotExposeSource(t *testing.T) {
	target, err := alerttarget.Parse("weather")
	if err != nil {
		t.Fatal(err)
	}

	result := entryResult(alertstore.Entry{
		Target: target,
		Kind:   alertstore.KindOversized,
		Size:   alertstore.MaxLegacyBytes + 1,
	})

	if result.Kind != "oversized" {
		t.Fatalf("Kind = %q; want oversized", result.Kind)
	}

	if result.Message != "" || result.LegacySource != "" {
		t.Fatal("oversized result exposed content")
	}
}

func TestIssueKindNames(t *testing.T) {
	tests := []struct {
		kind alertstore.IssueKind
		want string
	}{
		{
			kind: alertstore.IssueMalformedName,
			want: "malformed_name",
		},
		{
			kind: alertstore.IssueUnsafeEntry,
			want: "unsafe_entry",
		},
		{
			kind: alertstore.IssueInspectionFailed,
			want: "inspection_failed",
		},
	}

	for _, test := range tests {
		if got := issueKindName(test.kind); got != test.want {
			t.Fatalf(
				"issueKindName(%v) = %q; want %q",
				test.kind,
				got,
				test.want,
			)
		}
	}
}

func TestResponseForErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{
			name: "invalid request",
			err:  ErrInvalidRequest,
			code: ErrorInvalidRequest,
		},
		{
			name: "oversized request",
			err:  ErrRequestTooLarge,
			code: ErrorInvalidRequest,
		},
		{
			name: "unsupported version",
			err:  ErrUnsupportedVersion,
			code: ErrorUnsupportedVersion,
		},
		{
			name: "unknown operation",
			err:  ErrUnknownOperation,
			code: ErrorUnknownOperation,
		},
		{
			name: "invalid target",
			err:  alertstore.ErrInvalidTarget,
			code: ErrorInvalidTarget,
		},
		{
			name: "invalid message",
			err:  alertstore.ErrInvalidMessage,
			code: ErrorInvalidMessage,
		},
		{
			name: "not found",
			err:  os.ErrNotExist,
			code: ErrorNotFound,
		},
		{
			name: "legacy conflict",
			err:  alertstore.ErrLegacyConflict,
			code: ErrorLegacyConflict,
		},
		{
			name: "oversized conflict",
			err:  alertstore.ErrOversizedConflict,
			code: ErrorOversizedConflict,
		},
		{
			name: "managed conflict",
			err:  alertstore.ErrManagedConflict,
			code: ErrorManagedConflict,
		},
		{
			name: "source changed",
			err:  alertstore.ErrSourceChanged,
			code: ErrorSourceChanged,
		},
		{
			name: "unsafe file",
			err:  alertstore.ErrUnsafeFile,
			code: ErrorUnsafeFile,
		},
		{
			name: "store closed",
			err:  alertstore.ErrClosed,
			code: ErrorStoreClosed,
		},
		{
			name: "unknown error",
			err:  errors.New("unexpected"),
			code: ErrorInternal,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := responseForError(test.err)

			if response.OK {
				t.Fatal("response unexpectedly successful")
			}

			if response.Error == nil {
				t.Fatal("response has no error")
			}

			if response.Error.Code != test.code {
				t.Fatalf(
					"Code = %q; want %q",
					response.Error.Code,
					test.code,
				)
			}
		})
	}
}
