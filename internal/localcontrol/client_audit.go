package localcontrol

import (
	"context"
	"fmt"

	"github.com/k2exe/aamm-ng/internal/auditidentity"
)

func actorFromContext(
	ctx context.Context,
) (string, error) {
	identity, ok := auditidentity.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf(
			"%w: authenticated actor required",
			ErrInvalidRequest,
		)
	}

	if err := validateActor(identity.Name); err != nil {
		return "", err
	}

	return identity.Name, nil
}
