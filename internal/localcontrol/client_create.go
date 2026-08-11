package localcontrol

import (
	"context"
	"fmt"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func (client *Client) Create(
	ctx context.Context,
	target string,
	message string,
) (CreateResult, error) {
	parsedTarget, err := alerttarget.Parse(target)
	if err != nil {
		return CreateResult{}, fmt.Errorf(
			"%w: invalid target",
			ErrInvalidRequest,
		)
	}

	parsedMessage, err := alertmessage.Parse(message)
	if err != nil {
		return CreateResult{}, fmt.Errorf(
			"%w: invalid message",
			ErrInvalidRequest,
		)
	}

	actor, err := actorFromContext(ctx)
	if err != nil {
		return CreateResult{}, err
	}

	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationCreate,
			Target:    parsedTarget.String(),
			Message:   parsedMessage.String(),
			Actor:     actor,
		},
	)
	if err != nil {
		return CreateResult{}, err
	}

	return decodeTypedResult[CreateResult](response)
}
