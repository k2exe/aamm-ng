package localcontrol

import (
	"context"
	"encoding/json"
	"fmt"
)

type RemoteError struct {
	Code    string
	Message string
}

func (err *RemoteError) Error() string {
	if err.Message != "" {
		return err.Message
	}

	return err.Code
}

func (client *Client) List(
	ctx context.Context,
) (ListResult, error) {
	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationList,
		},
	)
	if err != nil {
		return ListResult{}, err
	}

	return decodeTypedResult[ListResult](response)
}

func decodeTypedResult[T any](
	response Response,
) (T, error) {
	var zero T

	if !response.OK {
		if response.Error == nil {
			return zero, fmt.Errorf(
				"%w: failed response missing error",
				ErrInvalidResponse,
			)
		}

		return zero, &RemoteError{
			Code:    response.Error.Code,
			Message: response.Error.Message,
		}
	}

	if response.Result == nil {
		return zero, fmt.Errorf(
			"%w: successful response missing result",
			ErrInvalidResponse,
		)
	}

	data, err := json.Marshal(response.Result)
	if err != nil {
		return zero, fmt.Errorf(
			"%w: encode result: %v",
			ErrInvalidResponse,
			err,
		)
	}

	var result T

	if err := json.Unmarshal(data, &result); err != nil {
		return zero, fmt.Errorf(
			"%w: decode result: %v",
			ErrInvalidResponse,
			err,
		)
	}

	return result, nil
}
