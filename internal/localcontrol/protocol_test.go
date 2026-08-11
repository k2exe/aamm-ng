package localcontrol

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestDecodeRequestAcceptsOperations(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		operation Operation
		actor     string
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
			name:      "create",
			input:     `{"version":1,"operation":"create","target":"all","message":"Net open","actor":"TEST-NODE-A"}`,
			actor:     "TEST-NODE-A",
			operation: OperationCreate,
		},
		{
			name:      "write",
			input:     `{"version":1,"operation":"write","target":"all","message":"Net open","actor":"TEST-NODE-A"}`,
			actor:     "TEST-NODE-A",
			operation: OperationWrite,
		},
		{
			name:      "convert",
			input:     `{"version":1,"operation":"convert","target":"all","message":"Replacement","actor":"TEST-NODE-A"}`,
			actor:     "TEST-NODE-A",
			operation: OperationConvert,
		},
		{
			name:      "delete",
			input:     `{"version":1,"operation":"delete","target":"all","actor":"TEST-NODE-A"}`,
			actor:     "TEST-NODE-A",
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

			if request.Actor != test.actor {
				t.Fatalf(
					"Actor = %q; want %q",
					request.Actor,
					test.actor,
				)
			}
		})
	}
}

func TestDecodeRequestRequiresActorForMutations(t *testing.T) {
	tests := []string{
		`{"version":1,"operation":"create","target":"all","message":"Net open"}`,
		`{"version":1,"operation":"write","target":"all","message":"Net open"}`,
		`{"version":1,"operation":"convert","target":"all","message":"Replacement"}`,
		`{"version":1,"operation":"delete","target":"all"}`,
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

func TestDecodeRequestRejectsUnsafeActor(t *testing.T) {
	tests := []string{
		"",
		" TEST-NODE-A",
		"TEST-NODE-A ",
		"TEST-NODE-A\nforged",
		"TEST-NODE-A\u202Eevil",
		strings.Repeat("x", MaxActorBytes+1),
	}

	for _, actor := range tests {
		t.Run(actor, func(t *testing.T) {
			input := `{"version":1,"operation":"delete","target":"all","actor":` +
				strconv.Quote(actor) +
				`}`

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
		OperationCreate,
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
		OperationCreate,
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

func TestDecodeRequestReturnsParsedMutationOnValidationError(
	t *testing.T,
) {
	request, err := DecodeRequest([]byte(
		`{"version":1,"operation":"write","target":"all","message":"test"}`,
	))

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"DecodeRequest() error = %v; want ErrInvalidRequest",
			err,
		)
	}

	if request.Operation != OperationWrite {
		t.Fatalf(
			"Operation = %q; want %q",
			request.Operation,
			OperationWrite,
		)
	}

	if request.Target != "all" {
		t.Fatalf(
			"Target = %q; want all",
			request.Target,
		)
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

func TestValidateMutationAuditAcceptsCompleteAttribution(t *testing.T) {
	err := validateMutationAudit(
		MutationAudit{
			AuthNode:   "TEST-NODE-A",
			AuthRole:   "admin",
			SourceIP:   "192.0.2.44",
			SourceNode: "TEST-NODE-B",
			SourceHost: "test-workstation",
		},
	)

	if err != nil {
		t.Fatalf("validateMutationAudit() error = %v", err)
	}
}

func TestValidateMutationAuditAcceptsRequiredFieldsOnly(t *testing.T) {
	err := validateMutationAudit(
		MutationAudit{
			AuthNode: "TEST-NODE-A",
			AuthRole: "admin",
			SourceIP: "192.0.2.44",
		},
	)

	if err != nil {
		t.Fatalf("validateMutationAudit() error = %v", err)
	}
}

func TestValidateMutationAuditRejectsInvalidRole(t *testing.T) {
	err := validateMutationAudit(
		MutationAudit{
			AuthNode: "TEST-NODE-A",
			AuthRole: "operator",
			SourceIP: "192.0.2.44",
		},
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v; want ErrInvalidRequest", err)
	}
}

func TestValidateMutationAuditRejectsNonCanonicalSourceAddress(t *testing.T) {
	err := validateMutationAudit(
		MutationAudit{
			AuthNode: "TEST-NODE-A",
			AuthRole: "admin",
			SourceIP: "::ffff:192.0.2.44",
		},
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v; want ErrInvalidRequest", err)
	}
}

func TestValidateMutationAuditRejectsHostWithoutNode(t *testing.T) {
	err := validateMutationAudit(
		MutationAudit{
			AuthNode:   "TEST-NODE-A",
			AuthRole:   "admin",
			SourceIP:   "192.0.2.44",
			SourceHost: "test-workstation",
		},
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v; want ErrInvalidRequest", err)
	}
}

func TestValidateMutationAuditRejectsUnsafeNodeName(t *testing.T) {
	err := validateMutationAudit(
		MutationAudit{
			AuthNode:   "TEST-NODE-A",
			AuthRole:   "admin",
			SourceIP:   "192.0.2.44",
			SourceNode: "TEST-NODE-B\nforged",
		},
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v; want ErrInvalidRequest", err)
	}
}
