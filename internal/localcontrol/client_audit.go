package localcontrol

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/k2exe/aamm-ng/internal/arednsource"
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

func (client *Client) sourceAttribution(
	ctx context.Context,
	sourceIP string,
) arednsource.Attribution {
	if client == nil || client.resolveSource == nil {
		return arednsource.Attribution{}
	}

	attribution, err := client.resolveSource(
		ctx,
		sourceIP,
	)
	if err != nil {
		return arednsource.Attribution{}
	}

	return attribution
}

type mutationAuditContext struct {
	AuthNode   string
	AuthRole   string
	SourceIP   string
	SourceNode string
	SourceHost string
}

func (client *Client) mutationAuditFromContext(
	ctx context.Context,
) (mutationAuditContext, error) {
	identity, ok := auditidentity.FromContext(ctx)
	if !ok {
		return mutationAuditContext{}, fmt.Errorf(
			"%w: authenticated identity required",
			ErrInvalidRequest,
		)
	}

	if err := validateActor(identity.Name); err != nil {
		return mutationAuditContext{}, err
	}

	sourceAddress, err := netip.ParseAddr(identity.SourceIP)
	if err != nil {
		return mutationAuditContext{}, fmt.Errorf(
			"%w: trusted source address required",
			ErrInvalidRequest,
		)
	}

	sourceIP := sourceAddress.Unmap().String()

	attribution := client.sourceAttribution(
		ctx,
		sourceIP,
	)

	return mutationAuditContext{
		AuthNode:   identity.Name,
		AuthRole:   "admin",
		SourceIP:   sourceIP,
		SourceNode: attribution.SourceNode,
		SourceHost: attribution.SourceHost,
	}, nil
}
