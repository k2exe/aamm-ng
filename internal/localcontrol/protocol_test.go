package localcontrol

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeRequestAcceptsOperations(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		operation Operation
	}{
		{
			name:      "list",
			input:     `{"version":1,"operation":"list"}`,
			operation: OperationList,
		},
		{
			name:      "read",
			input:     `{"version":1,"operation":"read","target":"all"}`,
			operation: OperationRead,
		},
		{
			name:      "write",
			input:     `{"version":1,"operation":"write","target":"all","message":"Net open"}`,
			operation: OperationWrite,
		},
		{
			name:      "convert",
			input:     `{"version":1,"operation":"convert","target":"all","message":"Replacement"}`,
			operation: OperationConvert,
		},
		{
			name:      "delete",
			input:     `{"version":1,"operation":"delete","target":"all"}`,
			operation: OperationDelete,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := DecodeRequest([]byte(test.input))
			if err != nil {
				t.Fatal(err)
			}

			if request.Operation != test.operation {
				t.Fatalf(
					"Operation = %q; want %q",
					request.Operation,
					test.operation,
				)
			}
		})
	}
}

func TestDecodeRequestRejectsOversizedInput(t *testing.T) {
	input := []byte(strings.Repeat("x", MaxRequestBytes+1))

	_, err := DecodeRequest(input)
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrRequestTooLarge",
			err,
		)
	}
}

func TestDecodeRequestRejectsUnsupportedVersion(t *testing.T) {
	_, err := DecodeRequest(
		[]byte(`{"version":2,"operation":"list"}`),
	)

	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrUnsupportedVersion",
			err,
		)
	}
}

func TestDecodeRequestRejectsUnknownOperation(t *testing.T) {
	_, err := DecodeRequest(
		[]byte(`{"version":1,"operation":"shell"}`),
	)

	if !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrUnknownOperation",
			err,
		)
	}
}

func TestDecodeRequestRejectsUnknownField(t *testing.T) {
	_, err := DecodeRequest(
		[]byte(`{"version":1,"operation":"list","path":"/etc"}`),
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestDecodeRequestRejectsMultipleValues(t *testing.T) {
	_, err := DecodeRequest(
		[]byte(
			`{"version":1,"operation":"list"} {"version":1,"operation":"list"}`,
		),
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrInvalidRequest",
			err,
		)
	}
}

func TestDecodeRequestRequiresTarget(t *testing.T) {
	for _, operation := range []Operation{
		OperationRead,
		OperationWrite,
		OperationConvert,
		OperationDelete,
	} {
		t.Run(string(operation), func(t *testing.T) {
			input := `{"version":1,"operation":"` +
				string(operation) +
				`","message":"message"}`

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

func TestDecodeRequestRequiresWriteMessage(t *testing.T) {
	for _, operation := range []Operation{
		OperationWrite,
		OperationConvert,
	} {
		t.Run(string(operation), func(t *testing.T) {
			input := `{"version":1,"operation":"` +
				string(operation) +
				`","target":"all"}`

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

func TestResponseConstructors(t *testing.T) {
	success := Success(map[string]string{"status": "ok"})

	if !success.OK || success.Error != nil {
		t.Fatalf("Success() = %#v", success)
	}

	failure := Failure("invalid_target", "invalid target")

	if failure.OK ||
		failure.Error == nil ||
		failure.Error.Code != "invalid_target" {
		t.Fatalf("Failure() = %#v", failure)
	}
}
