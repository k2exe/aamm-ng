package localcontrol

import (
	"errors"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

type SettingsStore interface {
	Current() appconfig.Config
	Replace(appconfig.Config) error
}

func DispatchWithSettings(
	store Store,
	settings SettingsStore,
	request Request,
) Response {
	switch request.Operation {
	case OperationSettingsRead:
		return dispatchSettingsRead(settings)

	case OperationSettingsReplace:
		return dispatchSettingsReplace(settings, request)

	default:
		return Dispatch(store, request)
	}
}

func dispatchSettingsRead(
	settings SettingsStore,
) Response {
	return Success(settings.Current())
}

func dispatchSettingsReplace(
	settings SettingsStore,
	request Request,
) Response {
	if request.Settings == nil {
		return responseForError(ErrInvalidRequest)
	}

	if err := settings.Replace(*request.Settings); err != nil {
		return responseForSettingsError(err)
	}

	return Success(settings.Current())
}

func responseForSettingsError(err error) Response {
	switch {
	case errors.Is(err, appconfig.ErrDurabilityUncertain):
		return Failure(
			ErrorSettingsDurabilityUncertain,
			"application settings applied; durability is uncertain",
		)

	case errors.Is(err, appconfig.ErrInvalidConfig),
		errors.Is(err, appconfig.ErrUnsupportedVersion),
		errors.Is(err, appconfig.ErrTooLarge):
		return Failure(
			ErrorInvalidSettings,
			"invalid application settings",
		)

	default:
		return Failure(
			ErrorInternal,
			"could not save application settings",
		)
	}
}
