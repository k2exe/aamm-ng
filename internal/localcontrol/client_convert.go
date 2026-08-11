package localcontrol

import (
	"context"
	"fmt"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func (client *Client) Convert(
	ctx context.Context,
	target string,
	message string,
) (ConvertResult, error) {
	parsedTarget, err := alerttarget.Parse(target)
	if err != nil {
		return ConvertResult{}, fmt.Errorf(
			"%w: invalid target",
			ErrInvalidRequest,
		)
	}

	parsedMessage, err := alertmessage.Parse(message)
	if err != nil {
		return ConvertResult{}, fmt.Errorf(
			"%w: invalid message",
			ErrInvalidRequest,
		)
	}

	actor, err := actorFromContext(ctx)
	if err != nil {
		return ConvertResult{}, err
	}

	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationConvert,
			Target:    parsedTarget.String(),
			Message:   parsedMessage.String(),
			Actor:     actor,
		},
	)
	if err != nil {
		return ConvertResult{}, err
	}

	return decodeTypedResult[ConvertResult](response)
}
