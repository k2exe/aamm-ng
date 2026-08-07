package localcontrol

import (
	"errors"
	"testing"

	"github.com/k2exe/aamm-ng/internal/alertstore"
)

func TestListingResultOmitsLegacySource(t *testing.T) {
	target := mustTarget(t, "all")

	result := listingResult(alertstore.Listing{
		Entries: []alertstore.Entry{
			{
				Target:     target,
				Kind:       alertstore.KindLegacy,
				LegacyHTML: "<script>legacy()</script>",
				Size:       25,
			},
		},
	})

	if len(result.Entries) != 1 {
		t.Fatalf(
			"entries = %d; want 1",
			len(result.Entries),
		)
	}

	entry := result.Entries[0]

	if entry.LegacySource != "" {
		t.Fatalf(
			"LegacySource = %q; want empty",
			entry.LegacySource,
		)
	}

	if entry.Target != "all" {
		t.Fatalf(
			"Target = %q; want all",
			entry.Target,
		)
	}

	if entry.Kind != "legacy" {
		t.Fatalf(
			"Kind = %q; want legacy",
			entry.Kind,
		)
	}

	if entry.Size != 25 {
		t.Fatalf(
			"Size = %d; want 25",
			entry.Size,
		)
	}
}

func TestDecodeTypedListResult(t *testing.T) {
	response := Response{
		Version: ProtocolVersion,
		OK:      true,
		Result: map[string]any{
			"entries": []any{
				map[string]any{
					"target":  "all",
					"kind":    "managed",
					"message": "Net open",
					"size":    float64(8),
				},
			},
			"issues": []any{},
		},
	}

	result, err := decodeTypedResult[ListResult](response)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 1 {
		t.Fatalf(
			"entries = %d; want 1",
			len(result.Entries),
		)
	}

	if result.Entries[0].Message != "Net open" {
		t.Fatalf(
			"Message = %q; want Net open",
			result.Entries[0].Message,
		)
	}
}

func TestDecodeTypedResultReturnsRemoteError(t *testing.T) {
	response := Failure(
		ErrorStoreClosed,
		"store closed",
	)

	_, err := decodeTypedResult[ListResult](response)

	var remoteErr *RemoteError

	if !errors.As(err, &remoteErr) {
		t.Fatalf(
			"error = %v; want RemoteError",
			err,
		)
	}

	if remoteErr.Code != ErrorStoreClosed {
		t.Fatalf(
			"Code = %q; want %q",
			remoteErr.Code,
			ErrorStoreClosed,
		)
	}
}

func TestDecodeTypedResultRequiresResult(t *testing.T) {
	_, err := decodeTypedResult[ListResult](Response{
		Version: ProtocolVersion,
		OK:      true,
	})

	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf(
			"error = %v; want ErrInvalidResponse",
			err,
		)
	}
}
