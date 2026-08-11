package localcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

const (
	ProtocolVersion = 1
	MaxRequestBytes = 16 * 1024
	MaxActorBytes   = 128
)

type Operation string

const (
	OperationList    Operation = "list"
	OperationRead    Operation = "read"
	OperationCreate  Operation = "create"
	OperationWrite   Operation = "write"
	OperationConvert Operation = "convert"
	OperationDelete  Operation = "delete"
)

var (
	ErrRequestTooLarge    = errors.New("control request exceeds size limit")
	ErrInvalidRequest     = errors.New("invalid control request")
	ErrUnsupportedVersion = errors.New("unsupported control protocol version")
	ErrUnknownOperation   = errors.New("unknown control operation")
)

type Request struct {
	Version   int       `json:"version"`
	Operation Operation `json:"operation"`
	Target    string    `json:"target,omitempty"`
	Message   string    `json:"message,omitempty"`
	Actor     string    `json:"actor,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

func DecodeRequest(data []byte) (Request, error) {
	if len(data) > MaxRequestBytes {
		return Request{}, ErrRequestTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var request Request

	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf(
			"%w: %v",
			ErrInvalidRequest,
			err,
		)
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Request{}, fmt.Errorf(
				"%w: multiple JSON values",
				ErrInvalidRequest,
			)
		}

		return Request{}, fmt.Errorf(
			"%w: trailing data: %v",
			ErrInvalidRequest,
			err,
		)
	}

	if err := validateRequest(request); err != nil {
		return Request{}, err
	}

	return request, nil
}

func validateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return fmt.Errorf(
			"%w: %d",
			ErrUnsupportedVersion,
			request.Version,
		)
	}

	switch request.Operation {
	case OperationList:
		if request.Target != "" ||
			request.Message != "" ||
			request.Actor != "" {
			return fmt.Errorf(
				"%w: list accepts no target, message, or actor",
				ErrInvalidRequest,
			)
		}

	case OperationRead:
		if request.Target == "" {
			return fmt.Errorf(
				"%w: read requires target",
				ErrInvalidRequest,
			)
		}

		if request.Message != "" || request.Actor != "" {
			return fmt.Errorf(
				"%w: read accepts no message or actor",
				ErrInvalidRequest,
			)
		}

	case OperationDelete:
		if request.Target == "" {
			return fmt.Errorf(
				"%w: delete requires target",
				ErrInvalidRequest,
			)
		}

		if request.Message != "" {
			return fmt.Errorf(
				"%w: delete accepts no message",
				ErrInvalidRequest,
			)
		}

		if err := validateActor(request.Actor); err != nil {
			return err
		}

	case OperationCreate, OperationWrite, OperationConvert:
		if request.Target == "" {
			return fmt.Errorf(
				"%w: %s requires target",
				ErrInvalidRequest,
				request.Operation,
			)
		}

		if request.Message == "" {
			return fmt.Errorf(
				"%w: %s requires message",
				ErrInvalidRequest,
				request.Operation,
			)
		}

		if err := validateActor(request.Actor); err != nil {
			return err
		}

	default:
		return fmt.Errorf(
			"%w: %q",
			ErrUnknownOperation,
			request.Operation,
		)
	}

	return nil
}

func validateActor(actor string) error {
	if actor == "" {
		return fmt.Errorf(
			"%w: mutating operation requires authenticated actor",
			ErrInvalidRequest,
		)
	}

	if len(actor) > MaxActorBytes {
		return fmt.Errorf(
			"%w: actor exceeds %d bytes",
			ErrInvalidRequest,
			MaxActorBytes,
		)
	}

	if strings.TrimSpace(actor) != actor {
		return fmt.Errorf(
			"%w: actor contains surrounding whitespace",
			ErrInvalidRequest,
		)
	}

	for _, value := range actor {
		if unicode.IsControl(value) ||
			unicode.In(value, unicode.Cf) {
			return fmt.Errorf(
				"%w: actor contains unsafe characters",
				ErrInvalidRequest,
			)
		}
	}

	return nil
}

func Success(result any) Response {
	return Response{
		Version: ProtocolVersion,
		OK:      true,
		Result:  result,
	}
}

func Failure(code string, message string) Response {
	return Response{
		Version: ProtocolVersion,
		OK:      false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	}
}
