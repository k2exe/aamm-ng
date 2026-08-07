package localcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolVersion = 1
	MaxRequestBytes = 16 * 1024
)

type Operation string

const (
	OperationList    Operation = "list"
	OperationRead    Operation = "read"
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
		if request.Target != "" || request.Message != "" {
			return fmt.Errorf(
				"%w: list accepts no target or message",
				ErrInvalidRequest,
			)
		}

	case OperationRead, OperationDelete:
		if request.Target == "" {
			return fmt.Errorf(
				"%w: %s requires target",
				ErrInvalidRequest,
				request.Operation,
			)
		}

		if request.Message != "" {
			return fmt.Errorf(
				"%w: %s accepts no message",
				ErrInvalidRequest,
				request.Operation,
			)
		}

	case OperationWrite, OperationConvert:
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

	default:
		return fmt.Errorf(
			"%w: %q",
			ErrUnknownOperation,
			request.Operation,
		)
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
