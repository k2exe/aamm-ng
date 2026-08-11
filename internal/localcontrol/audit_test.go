package localcontrol

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteMutationAuditSuccess(t *testing.T) {
	var output bytes.Buffer

	now := time.Date(
		2026, time.August, 11,
		4, 24, 30, 0,
		time.UTC,
	)

	request := Request{
		Version:   ProtocolVersion,
		Operation: OperationWrite,
		Target:    "all",
		Message:   "SECRET MESSAGE MUST NOT BE LOGGED",
		Audit:     testMutationAudit(),
	}

	writeMutationAudit(
		&output,
		now,
		request,
		Success(WriteResult{
			Target: "all",
			Kind:   "managed",
		}),
	)

	got := output.String()

	for _, expected := range []string{
		`aamm-ng audit`,
		`timestamp=2026-08-11T04:24:30Z`,
		`auth_node="TEST-NODE-A"`,
		`auth_role="admin"`,
		`source_ip="192.0.2.44"`,
		`source_node="TEST-NODE-B"`,
		`source_host="test-workstation"`,
		`operation="write"`,
		`target="all"`,
		`outcome="success"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf(
				"audit record missing %q: %q",
				expected,
				got,
			)
		}
	}

	if strings.Contains(
		got,
		"SECRET MESSAGE MUST NOT BE LOGGED",
	) {
		t.Fatalf(
			"audit record leaked message body: %q",
			got,
		)
	}
}

func TestWriteMutationAuditFailure(t *testing.T) {
	var output bytes.Buffer

	now := time.Date(
		2026, time.August, 11,
		4, 25, 0, 0,
		time.UTC,
	)

	writeMutationAudit(
		&output,
		now,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationDelete,
			Target:    "weather",
			Audit:     testMutationAudit(),
		},
		Failure(
			ErrorOversizedConflict,
			"detail must not be logged",
		),
	)

	got := output.String()

	for _, expected := range []string{
		`auth_node="TEST-NODE-A"`,
		`auth_role="admin"`,
		`source_ip="192.0.2.44"`,
		`source_node="TEST-NODE-B"`,
		`source_host="test-workstation"`,
		`operation="delete"`,
		`target="weather"`,
		`outcome="failure"`,
		`error_code="oversized_conflict"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf(
				"audit record missing %q: %q",
				expected,
				got,
			)
		}
	}

	if strings.Contains(got, "detail must not be logged") {
		t.Fatalf(
			"audit record leaked error detail: %q",
			got,
		)
	}
}

func TestWriteMutationAuditOmitsUnavailableSourceMetadata(t *testing.T) {
	var output bytes.Buffer

	audit := testRequiredMutationAudit()

	writeMutationAudit(
		&output,
		time.Now(),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationDelete,
			Target:    "all",
			Audit:     &audit,
		},
		Success(DeleteResult{
			Target: "all",
		}),
	)

	got := output.String()

	for _, expected := range []string{
		`auth_node="TEST-NODE-A"`,
		`auth_role="admin"`,
		`source_ip="192.0.2.44"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf(
				"audit record missing %q: %q",
				expected,
				got,
			)
		}
	}

	for _, forbidden := range []string{
		"source_node=",
		"source_host=",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf(
				"audit record unexpectedly contains %q: %q",
				forbidden,
				got,
			)
		}
	}
}

func TestWriteMutationAuditIgnoresReadOperations(t *testing.T) {
	var output bytes.Buffer

	writeMutationAudit(
		&output,
		time.Now(),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationRead,
			Target:    "all",
		},
		Success(nil),
	)

	if output.Len() != 0 {
		t.Fatalf(
			"read operation produced audit output: %q",
			output.String(),
		)
	}
}

func TestWriteMutationAuditQuotesUnsafeTarget(t *testing.T) {
	var output bytes.Buffer

	writeMutationAudit(
		&output,
		time.Date(
			2026, time.August, 11,
			4, 25, 30, 0,
			time.UTC,
		),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationDelete,
			Target:    "all\nforged-entry",
			Audit:     testMutationAudit(),
		},
		Failure(
			ErrorInvalidTarget,
			"invalid target",
		),
	)

	got := output.String()

	if strings.Count(got, "\n") != 1 {
		t.Fatalf(
			"audit target injected additional log line: %q",
			got,
		)
	}

	if !strings.Contains(
		got,
		`target="all\nforged-entry"`,
	) {
		t.Fatalf(
			"unsafe target was not quoted: %q",
			got,
		)
	}
}
