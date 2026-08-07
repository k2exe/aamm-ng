package localcontrol

import (
	"fmt"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alertstore"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

type Store interface {
	List() (alertstore.Listing, error)
	Read(alerttarget.Target) (alertstore.Entry, error)
	Write(alerttarget.Target, alertmessage.Message) error
	ConvertLegacy(
		alerttarget.Target,
		alertmessage.Message,
	) (alertstore.ConversionResult, error)
	Delete(alerttarget.Target) (alertstore.DeleteResult, error)
}

func Dispatch(store Store, request Request) Response {
	switch request.Operation {
	case OperationList:
		return dispatchList(store)

	case OperationRead:
		return dispatchRead(store, request)

	case OperationWrite:
		return dispatchWrite(store, request)

	case OperationConvert:
		return dispatchConvert(store, request)

	case OperationDelete:
		return dispatchDelete(store, request)

	default:
		return Failure(
			ErrorUnknownOperation,
			fmt.Sprintf(
				"unknown control operation %q",
				request.Operation,
			),
		)
	}
}

func dispatchList(store Store) Response {
	listing, err := store.List()
	if err != nil {
		return responseForError(err)
	}

	return Success(listingResult(listing))
}

func dispatchRead(store Store, request Request) Response {
	target, response, ok := parseTarget(request.Target)
	if !ok {
		return response
	}

	entry, err := store.Read(target)
	if err != nil {
		return responseForError(err)
	}

	return Success(entryResult(entry))
}

func dispatchWrite(store Store, request Request) Response {
	target, response, ok := parseTarget(request.Target)
	if !ok {
		return response
	}

	message, response, ok := parseMessage(request.Message)
	if !ok {
		return response
	}

	if err := store.Write(target, message); err != nil {
		return responseForError(err)
	}

	return Success(WriteResult{
		Target: target.String(),
		Kind:   "managed",
	})
}

func dispatchConvert(store Store, request Request) Response {
	target, response, ok := parseTarget(request.Target)
	if !ok {
		return response
	}

	message, response, ok := parseMessage(request.Message)
	if !ok {
		return response
	}

	result, err := store.ConvertLegacy(target, message)
	if err != nil {
		return responseForError(err)
	}

	return Success(ConvertResult{
		Target:     target.String(),
		Kind:       "managed",
		BackupName: result.BackupName,
	})
}

func dispatchDelete(store Store, request Request) Response {
	target, response, ok := parseTarget(request.Target)
	if !ok {
		return response
	}

	result, err := store.Delete(target)
	if err != nil {
		return responseForError(err)
	}

	return Success(DeleteResult{
		Target:     target.String(),
		BackupName: result.BackupName,
	})
}

func parseTarget(
	value string,
) (alerttarget.Target, Response, bool) {
	target, err := alerttarget.Parse(value)
	if err != nil {
		return alerttarget.Target{},
			Failure(ErrorInvalidTarget, err.Error()),
			false
	}

	return target, Response{}, true
}

func parseMessage(
	value string,
) (alertmessage.Message, Response, bool) {
	message, err := alertmessage.Parse(value)
	if err != nil {
		return alertmessage.Message{},
			Failure(ErrorInvalidMessage, err.Error()),
			false
	}

	return message, Response{}, true
}
