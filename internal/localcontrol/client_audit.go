package localcontrol

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/k2exe/aamm-ng/internal/arednsource"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
)

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

func (client *Client) mutationAuditFromContext(
	ctx context.Context,
) (MutationAudit, error) {
	identity, ok := auditidentity.FromContext(ctx)
	if !ok {
		return MutationAudit{}, fmt.Errorf(
			"%w: authenticated identity required",
			ErrInvalidRequest,
		)
	}

	sourceAddress, err := netip.ParseAddr(identity.SourceIP)
	if err != nil {
		return MutationAudit{}, fmt.Errorf(
			"%w: trusted source address required",
			ErrInvalidRequest,
		)
	}

	sourceIP := sourceAddress.Unmap().String()

	attribution := client.sourceAttribution(
		ctx,
		sourceIP,
	)

	audit := MutationAudit{
		AuthNode:   identity.Name,
		AuthRole:   "admin",
		SourceIP:   sourceIP,
		SourceNode: attribution.SourceNode,
		SourceHost: attribution.SourceHost,
	}

	if err := validateMutationAudit(audit); err != nil {
		return MutationAudit{}, err
	}

	return audit, nil
}
