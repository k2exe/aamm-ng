package localcontrol

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

func TestWriteMutationAuditSettingsReplace(t *testing.T) {
	var output bytes.Buffer

	settings := appconfig.Defaults()

	writeMutationAudit(
		&output,
		time.Date(
			2026, time.August, 12,
			20, 50, 0, 0,
			time.UTC,
		),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
			Settings:  &settings,
			Audit:     testMutationAudit(),
		},
		Success(settings),
	)

	got := output.String()

	for _, expected := range []string{
		`aamm-ng audit`,
		`auth_node="TEST-NODE-A"`,
		`auth_role="admin"`,
		`source_ip="192.0.2.44"`,
		`operation="settings_replace"`,
		`target=""`,
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

	if strings.Contains(got, `"version"`) {
		t.Fatalf(
			"audit record leaked settings payload: %q",
			got,
		)
	}
}

func TestWriteRejectedMutationAuditSettingsReplace(t *testing.T) {
	var output bytes.Buffer

	settings := appconfig.Defaults()

	writeRejectedMutationAudit(
		&output,
		time.Date(
			2026, time.August, 12,
			20, 51, 0, 0,
			time.UTC,
		),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
			Settings:  &settings,
			Audit:     testMutationAudit(),
		},
		Failure(
			ErrorInvalidSettings,
			"invalid application settings",
		),
	)

	got := output.String()

	for _, expected := range []string{
		`operation="settings_replace"`,
		`outcome="failure"`,
		`error_code="invalid_settings"`,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf(
				"rejected audit record missing %q: %q",
				expected,
				got,
			)
		}
	}

	if strings.Contains(got, `"version"`) {
		t.Fatalf(
			"rejected audit record leaked settings payload: %q",
			got,
		)
	}
}

func TestWriteMutationAuditIgnoresSettingsRead(t *testing.T) {
	var output bytes.Buffer

	writeMutationAudit(
		&output,
		time.Now(),
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsRead,
		},
		Success(appconfig.Defaults()),
	)

	if output.Len() != 0 {
		t.Fatalf(
			"settings read produced audit output: %q",
			output.String(),
		)
	}
}
