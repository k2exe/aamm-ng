package localcontrol

import (
	"errors"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

func TestDispatchWithSettingsReadsCurrentConfig(t *testing.T) {
	settings := &fakeSettingsStore{
		current: appconfig.Defaults(),
	}

	response := DispatchWithSettings(
		&fakeStore{},
		settings,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsRead,
		},
	)

	if !response.OK {
		t.Fatalf(
			"DispatchWithSettings() = %#v; want success",
			response,
		)
	}

	if settings.currentCalls != 1 {
		t.Fatalf(
			"Current calls = %d; want 1",
			settings.currentCalls,
		)
	}

	result, ok := response.Result.(appconfig.Config)
	if !ok {
		t.Fatalf(
			"Result type = %T; want appconfig.Config",
			response.Result,
		)
	}

	if result != appconfig.Defaults() {
		t.Fatalf(
			"Result = %#v; want %#v",
			result,
			appconfig.Defaults(),
		)
	}
}

func TestDispatchWithSettingsReplacesConfig(t *testing.T) {
	settings := &fakeSettingsStore{
		current: appconfig.Defaults(),
	}
	replacement := appconfig.Defaults()

	response := DispatchWithSettings(
		&fakeStore{},
		settings,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
			Settings:  &replacement,
		},
	)

	if !response.OK {
		t.Fatalf(
			"DispatchWithSettings() = %#v; want success",
			response,
		)
	}

	if settings.replaceCalls != 1 {
		t.Fatalf(
			"Replace calls = %d; want 1",
			settings.replaceCalls,
		)
	}

	if settings.replaced != replacement {
		t.Fatalf(
			"replaced config = %#v; want %#v",
			settings.replaced,
			replacement,
		)
	}
}

func TestDispatchWithSettingsRejectsMissingReplacement(t *testing.T) {
	settings := &fakeSettingsStore{}

	response := DispatchWithSettings(
		&fakeStore{},
		settings,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
		},
	)

	if response.OK {
		t.Fatalf(
			"DispatchWithSettings() = %#v; want failure",
			response,
		)
	}

	if settings.replaceCalls != 0 {
		t.Fatalf(
			"Replace calls = %d; want 0",
			settings.replaceCalls,
		)
	}
}

func TestDispatchWithSettingsReportsReplaceFailure(t *testing.T) {
	settings := &fakeSettingsStore{
		replaceErr: errors.New("test persistence failure"),
	}
	replacement := appconfig.Defaults()

	response := DispatchWithSettings(
		&fakeStore{},
		settings,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
			Settings:  &replacement,
		},
	)

	if response.OK {
		t.Fatalf(
			"DispatchWithSettings() = %#v; want failure",
			response,
		)
	}

	if settings.replaceCalls != 1 {
		t.Fatalf(
			"Replace calls = %d; want 1",
			settings.replaceCalls,
		)
	}
}

type fakeSettingsStore struct {
	current      appconfig.Config
	currentCalls int

	replaced     appconfig.Config
	replaceErr   error
	replaceCalls int
}

func (store *fakeSettingsStore) Current() appconfig.Config {
	store.currentCalls++
	return store.current
}

func (store *fakeSettingsStore) Replace(
	config appconfig.Config,
) error {
	store.replaceCalls++
	store.replaced = config

	if store.replaceErr != nil {
		return store.replaceErr
	}

	store.current = config
	return nil
}

func TestDispatchWithSettingsMapsInvalidConfig(t *testing.T) {
	tests := []error{
		appconfig.ErrInvalidConfig,
		appconfig.ErrUnsupportedVersion,
		appconfig.ErrTooLarge,
	}

	for _, replaceErr := range tests {
		t.Run(replaceErr.Error(), func(t *testing.T) {
			settings := &fakeSettingsStore{
				replaceErr: replaceErr,
			}
			replacement := appconfig.Defaults()

			response := DispatchWithSettings(
				&fakeStore{},
				settings,
				Request{
					Version:   ProtocolVersion,
					Operation: OperationSettingsReplace,
					Settings:  &replacement,
				},
			)

			requireErrorCode(
				t,
				response,
				ErrorInvalidSettings,
			)

			if response.Error.Message != "invalid application settings" {
				t.Fatalf(
					"error message = %q; want safe settings message",
					response.Error.Message,
				)
			}
		})
	}
}

func TestDispatchWithSettingsDoesNotLeakPersistenceError(t *testing.T) {
	const sensitive = "/private/test/settings/config.json"

	settings := &fakeSettingsStore{
		replaceErr: errors.New(
			"rename " + sensitive + ": permission denied",
		),
	}
	replacement := appconfig.Defaults()

	response := DispatchWithSettings(
		&fakeStore{},
		settings,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
			Settings:  &replacement,
		},
	)

	requireErrorCode(
		t,
		response,
		ErrorInternal,
	)

	if response.Error.Message != "could not save application settings" {
		t.Fatalf(
			"error message = %q; want safe persistence message",
			response.Error.Message,
		)
	}

	if strings.Contains(response.Error.Message, sensitive) {
		t.Fatalf(
			"error message leaked persistence path: %q",
			response.Error.Message,
		)
	}
}

func TestDispatchWithSettingsReportsDurabilityWarning(
	t *testing.T,
) {
	settings := &fakeSettingsStore{
		current:    appconfig.Defaults(),
		replaceErr: appconfig.ErrDurabilityUncertain,
	}

	replacement := appconfig.Defaults()

	response := DispatchWithSettings(
		&fakeStore{},
		settings,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
			Settings:  &replacement,
		},
	)

	if response.OK {
		t.Fatalf(
			"DispatchWithSettings() = %#v; want warning response",
			response,
		)
	}

	requireErrorCode(
		t,
		response,
		ErrorSettingsDurabilityUncertain,
	)

	if response.Error.Message !=
		"application settings applied; durability is uncertain" {
		t.Fatalf(
			"error message = %q; want safe durability warning",
			response.Error.Message,
		)
	}
}
