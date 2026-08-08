package localcontrol

import (
	"testing"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alertstore"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func TestDispatchList(t *testing.T) {
	store := &fakeStore{
		listing: alertstore.Listing{},
	}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationList,
	})

	if !response.OK {
		t.Fatalf("Dispatch() = %#v; want success", response)
	}

	if store.listCalls != 1 {
		t.Fatalf("List calls = %d; want 1", store.listCalls)
	}
}

func TestDispatchRead(t *testing.T) {
	target := mustTarget(t, "all")

	store := &fakeStore{
		entry: alertstore.Entry{
			Target: target,
			Kind:   alertstore.KindLegacy,
			Size:   6,
		},
	}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationRead,
		Target:    "all",
	})

	if !response.OK {
		t.Fatalf("Dispatch() = %#v; want success", response)
	}

	if store.readTarget.String() != "all" {
		t.Fatalf(
			"Read target = %q; want all",
			store.readTarget.String(),
		)
	}
}

func TestDispatchCreateValidatesAndCallsStore(t *testing.T) {
	store := &fakeStore{}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationCreate,
		Target:    "ALL",
		Message:   "Net open",
	})

	if !response.OK {
		t.Fatalf("Dispatch() = %#v; want success", response)
	}

	if store.createTarget.String() != "all" {
		t.Fatalf(
			"Create target = %q; want all",
			store.createTarget.String(),
		)
	}

	if store.createMessage.String() != "Net open" {
		t.Fatalf(
			"Create message = %q; want Net open",
			store.createMessage.String(),
		)
	}

	result, ok := response.Result.(CreateResult)
	if !ok {
		t.Fatalf(
			"Result type = %T; want CreateResult",
			response.Result,
		)
	}

	if result.Target != "all" || result.Kind != "managed" {
		t.Fatalf("CreateResult = %#v", result)
	}
}

func TestDispatchCreateMapsExistingAlertConflict(t *testing.T) {
	store := &fakeStore{
		createErr: alertstore.ErrAlreadyExists,
	}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationCreate,
		Target:    "all",
		Message:   "Net open",
	})

	requireErrorCode(t, response, ErrorAlreadyExists)
}

func TestDispatchWriteValidatesAndCallsStore(t *testing.T) {
	store := &fakeStore{}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationWrite,
		Target:    "ALL",
		Message:   "Net open",
	})

	if !response.OK {
		t.Fatalf("Dispatch() = %#v; want success", response)
	}

	if store.writeTarget.String() != "all" {
		t.Fatalf(
			"Write target = %q; want all",
			store.writeTarget.String(),
		)
	}

	if store.writeMessage.String() != "Net open" {
		t.Fatalf(
			"Write message = %q; want Net open",
			store.writeMessage.String(),
		)
	}
}

func TestDispatchConvertReturnsBackup(t *testing.T) {
	store := &fakeStore{
		conversionResult: alertstore.ConversionResult{
			BackupName: "backup.txt",
		},
	}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationConvert,
		Target:    "all",
		Message:   "Replacement",
	})

	if !response.OK {
		t.Fatalf("Dispatch() = %#v; want success", response)
	}

	result, ok := response.Result.(ConvertResult)
	if !ok {
		t.Fatalf(
			"Result type = %T; want ConvertResult",
			response.Result,
		)
	}

	if result.BackupName != "backup.txt" {
		t.Fatalf(
			"BackupName = %q; want backup.txt",
			result.BackupName,
		)
	}
}

func TestDispatchDeleteReturnsBackup(t *testing.T) {
	store := &fakeStore{
		deleteResult: alertstore.DeleteResult{
			BackupName: "deleted.txt",
		},
	}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationDelete,
		Target:    "all",
	})

	if !response.OK {
		t.Fatalf("Dispatch() = %#v; want success", response)
	}

	result, ok := response.Result.(DeleteResult)
	if !ok {
		t.Fatalf(
			"Result type = %T; want DeleteResult",
			response.Result,
		)
	}

	if result.BackupName != "deleted.txt" {
		t.Fatalf(
			"BackupName = %q; want deleted.txt",
			result.BackupName,
		)
	}
}

func TestDispatchRejectsInvalidTargetBeforeStore(t *testing.T) {
	store := &fakeStore{}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationRead,
		Target:    "../etc/passwd",
	})

	requireErrorCode(t, response, ErrorInvalidTarget)

	if store.readCalls != 0 {
		t.Fatal("store Read called for invalid target")
	}
}

func TestDispatchRejectsInvalidMessageBeforeStore(t *testing.T) {
	store := &fakeStore{}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationWrite,
		Target:    "all",
		Message:   "bad\x00message",
	})

	requireErrorCode(t, response, ErrorInvalidMessage)

	if store.writeCalls != 0 {
		t.Fatal("store Write called for invalid message")
	}
}

func TestDispatchMapsStoreErrors(t *testing.T) {
	store := &fakeStore{
		readErr: alertstore.ErrUnsafeFile,
	}

	response := Dispatch(store, Request{
		Version:   ProtocolVersion,
		Operation: OperationRead,
		Target:    "all",
	})

	requireErrorCode(t, response, ErrorUnsafeFile)
}

func TestDispatchUnknownOperation(t *testing.T) {
	response := Dispatch(&fakeStore{}, Request{
		Version:   ProtocolVersion,
		Operation: Operation("shell"),
	})

	requireErrorCode(t, response, ErrorUnknownOperation)
}

func requireErrorCode(
	t *testing.T,
	response Response,
	code string,
) {
	t.Helper()

	if response.OK {
		t.Fatalf("response unexpectedly successful: %#v", response)
	}

	if response.Error == nil {
		t.Fatalf("response has no error: %#v", response)
	}

	if response.Error.Code != code {
		t.Fatalf(
			"error code = %q; want %q",
			response.Error.Code,
			code,
		)
	}
}

func mustTarget(t *testing.T, value string) alerttarget.Target {
	t.Helper()

	target, err := alerttarget.Parse(value)
	if err != nil {
		t.Fatal(err)
	}

	return target
}

type fakeStore struct {
	listing    alertstore.Listing
	listErr    error
	listCalls  int
	entry      alertstore.Entry
	readErr    error
	readCalls  int
	readTarget alerttarget.Target

	createErr     error
	createCalls   int
	createTarget  alerttarget.Target
	createMessage alertmessage.Message

	writeErr     error
	writeCalls   int
	writeTarget  alerttarget.Target
	writeMessage alertmessage.Message

	conversionResult alertstore.ConversionResult
	conversionErr    error
	conversionCalls  int

	deleteResult alertstore.DeleteResult
	deleteErr    error
	deleteCalls  int
}

func (store *fakeStore) List() (alertstore.Listing, error) {
	store.listCalls++
	return store.listing, store.listErr
}

func (store *fakeStore) Read(
	target alerttarget.Target,
) (alertstore.Entry, error) {
	store.readCalls++
	store.readTarget = target
	return store.entry, store.readErr
}

func (store *fakeStore) Create(
	target alerttarget.Target,
	message alertmessage.Message,
) error {
	store.createCalls++
	store.createTarget = target
	store.createMessage = message
	return store.createErr
}

func (store *fakeStore) Write(
	target alerttarget.Target,
	message alertmessage.Message,
) error {
	store.writeCalls++
	store.writeTarget = target
	store.writeMessage = message
	return store.writeErr
}

func (store *fakeStore) ConvertLegacy(
	target alerttarget.Target,
	message alertmessage.Message,
) (alertstore.ConversionResult, error) {
	store.conversionCalls++

	if store.conversionErr != nil {
		return alertstore.ConversionResult{},
			store.conversionErr
	}

	return store.conversionResult, nil
}

func (store *fakeStore) Delete(
	target alerttarget.Target,
) (alertstore.DeleteResult, error) {
	store.deleteCalls++

	if store.deleteErr != nil {
		return alertstore.DeleteResult{}, store.deleteErr
	}

	return store.deleteResult, nil
}

var _ Store = (*fakeStore)(nil)
