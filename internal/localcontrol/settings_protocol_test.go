package localcontrol

import (
	"errors"
	"testing"
)

func TestDecodeRequestAcceptsSettingsRead(t *testing.T) {
	request, err := DecodeRequest(
		[]byte(`{"version":2,"operation":"settings_read"}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	if request.Operation != OperationSettingsRead {
		t.Fatalf(
			"Operation = %q; want %q",
			request.Operation,
			OperationSettingsRead,
		)
	}
}

func TestDecodeRequestAcceptsSettingsReplace(t *testing.T) {
	request, err := DecodeRequest([]byte(
		`{"version":2,"operation":"settings_replace","settings":{"version":1},"audit":{"auth_node":"TEST-NODE-A","auth_role":"admin","source_ip":"192.0.2.44"}}`,
	))
	if err != nil {
		t.Fatal(err)
	}

	if request.Operation != OperationSettingsReplace {
		t.Fatalf(
			"Operation = %q; want %q",
			request.Operation,
			OperationSettingsReplace,
		)
	}

	if request.Settings == nil {
		t.Fatal("Settings = nil; want configuration")
	}

	if request.Settings.Version != 1 {
		t.Fatalf(
			"Settings.Version = %d; want 1",
			request.Settings.Version,
		)
	}
}

func TestDecodeRequestSettingsReplaceRequiresAudit(t *testing.T) {
	_, err := DecodeRequest([]byte(
		`{"version":2,"operation":"settings_replace","settings":{"version":1}}`,
	))

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestDecodeRequestSettingsReplaceRequiresSettings(t *testing.T) {
	_, err := DecodeRequest([]byte(
		`{"version":2,"operation":"settings_replace","audit":{"auth_node":"TEST-NODE-A","auth_role":"admin","source_ip":"192.0.2.44"}}`,
	))

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestDecodeRequestSettingsReadRejectsExtraFields(t *testing.T) {
	tests := []string{
		`{"version":2,"operation":"settings_read","target":"all"}`,
		`{"version":2,"operation":"settings_read","message":"test"}`,
		`{"version":2,"operation":"settings_read","settings":{"version":1}}`,
		`{"version":2,"operation":"settings_read","audit":{"auth_node":"TEST-NODE-A","auth_role":"admin","source_ip":"192.0.2.44"}}`,
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := DecodeRequest([]byte(input))

			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf(
					"DecodeRequest() error = %v; want ErrInvalidRequest",
					err,
				)
			}
		})
	}
}

func TestDecodeRequestAlertOperationRejectsSettings(t *testing.T) {
	_, err := DecodeRequest([]byte(
		`{"version":2,"operation":"list","settings":{"version":1}}`,
	))

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrInvalidRequest",
			err,
		)
	}
}
