package localcontrol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const MaxResponseBytes = 1 << 20

var (
	ErrResponseTooLarge   = errors.New("control response exceeds size limit")
	ErrInvalidResponse    = errors.New("invalid control response")
	ErrControlUnavailable = errors.New("local control unavailable")
)

type Client struct {
	socketPath string
}

func NewClient() *Client {
	return &Client{
		socketPath: ProductionSocketPath,
	}
}

func (client *Client) Call(
	ctx context.Context,
	request Request,
) (Response, error) {
	requestData, err := json.Marshal(request)
	if err != nil {
		return Response{}, fmt.Errorf(
			"encode control request: %w",
			err,
		)
	}

	if _, err := DecodeRequest(requestData); err != nil {
		return Response{}, err
	}

	dialer := &net.Dialer{
		Timeout: ioTimeout,
	}

	connection, err := dialer.DialContext(
		ctx,
		"unix",
		client.socketPath,
	)
	if err != nil {
		return Response{}, clientIOError(
			ctx,
			"connect",
			err,
		)
	}
	defer connection.Close()

	deadline := time.Now().Add(ioTimeout)

	if contextDeadline, ok := ctx.Deadline(); ok &&
		contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	if err := connection.SetDeadline(deadline); err != nil {
		return Response{}, fmt.Errorf(
			"%w: set deadline: %v",
			ErrControlUnavailable,
			err,
		)
	}

	cancelWatchDone := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			_ = connection.SetDeadline(time.Now())
		case <-cancelWatchDone:
		}
	}()

	defer close(cancelWatchDone)

	wireRequest := append(requestData, '\n')

	if _, err := io.Copy(
		connection,
		bytes.NewReader(wireRequest),
	); err != nil {
		return Response{}, clientIOError(
			ctx,
			"write request",
			err,
		)
	}

	responseData, err := readResponse(connection)
	if err != nil {
		if errors.Is(err, ErrResponseTooLarge) ||
			errors.Is(err, ErrInvalidResponse) {
			return Response{}, err
		}

		return Response{}, clientIOError(
			ctx,
			"read response",
			err,
		)
	}

	return decodeResponse(responseData)
}

func readResponse(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(
		reader,
		MaxResponseBytes+2,
	)

	buffered := bufio.NewReader(limited)

	line, err := buffered.ReadBytes('\n')

	if len(line) > MaxResponseBytes+1 {
		return nil, ErrResponseTooLarge
	}

	if err != nil {
		if errors.Is(err, io.EOF) {
			if len(line) > MaxResponseBytes {
				return nil, ErrResponseTooLarge
			}

			return nil, fmt.Errorf(
				"%w: newline terminator required",
				ErrInvalidResponse,
			)
		}

		return nil, err
	}

	line = line[:len(line)-1]

	if len(line) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}

	return line, nil
}

func decodeResponse(data []byte) (Response, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var response Response

	if err := decoder.Decode(&response); err != nil {
		return Response{}, fmt.Errorf(
			"%w: %v",
			ErrInvalidResponse,
			err,
		)
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Response{}, fmt.Errorf(
				"%w: multiple JSON values",
				ErrInvalidResponse,
			)
		}

		return Response{}, fmt.Errorf(
			"%w: trailing data: %v",
			ErrInvalidResponse,
			err,
		)
	}

	if response.Version != ProtocolVersion {
		return Response{}, fmt.Errorf(
			"%w: unsupported version %d",
			ErrInvalidResponse,
			response.Version,
		)
	}

	if response.OK {
		if response.Error != nil {
			return Response{}, fmt.Errorf(
				"%w: successful response contains error",
				ErrInvalidResponse,
			)
		}

		return response, nil
	}

	if response.Error == nil || response.Error.Code == "" {
		return Response{}, fmt.Errorf(
			"%w: failed response missing error",
			ErrInvalidResponse,
		)
	}

	if response.Result != nil {
		return Response{}, fmt.Errorf(
			"%w: failed response contains result",
			ErrInvalidResponse,
		)
	}

	return response, nil
}

func clientIOError(
	ctx context.Context,
	action string,
	err error,
) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf(
			"control %s: %w",
			action,
			ctxErr,
		)
	}

	return fmt.Errorf(
		"%w: %s: %v",
		ErrControlUnavailable,
		action,
		err,
	)
}
