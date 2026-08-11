package localcontrol

import (
	"context"
	"fmt"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func (client *Client) Delete(
	ctx context.Context,
	target string,
) (DeleteResult, error) {
	parsedTarget, err := alerttarget.Parse(target)
	if err != nil {
		return DeleteResult{}, fmt.Errorf(
			"%w: invalid target",
			ErrInvalidRequest,
		)
	}

	actor, err := actorFromContext(ctx)
	if err != nil {
		return DeleteResult{}, err
	}

	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationDelete,
			Target:    parsedTarget.String(),
			Actor:     actor,
		},
	)
	if err != nil {
		return DeleteResult{}, err
	}

	return decodeTypedResult[DeleteResult](response)
}
