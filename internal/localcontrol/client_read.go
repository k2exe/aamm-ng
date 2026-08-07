package localcontrol

import (
	"context"
	"fmt"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func (client *Client) Read(
	ctx context.Context,
	target string,
) (EntryResult, error) {
	parsedTarget, err := alerttarget.Parse(target)
	if err != nil {
		return EntryResult{}, fmt.Errorf(
			"%w: invalid target",
			ErrInvalidRequest,
		)
	}

	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationRead,
			Target:    parsedTarget.String(),
		},
	)
	if err != nil {
		return EntryResult{}, err
	}

	return decodeTypedResult[EntryResult](response)
}
