package localcontrol

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

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

	if err := validateAuditText(
		"source node",
		attribution.SourceNode,
		MaxSourceNodeBytes,
		false,
	); err != nil {
		return arednsource.Attribution{}
	}

	if attribution.SourceNode == "" {
		return arednsource.Attribution{}
	}

	if err := validateAuditText(
		"source host",
		attribution.SourceHost,
		MaxSourceHostBytes,
		false,
	); err != nil {
		attribution.SourceHost = ""
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

	if client != nil &&
		client.lookupDHCPHost != nil &&
		attribution.SourceNode != "" &&
		attribution.SourceHost == "" &&
		strings.EqualFold(
			attribution.SourceNode,
			identity.Name,
		) {
		host, lookupErr := client.lookupDHCPHost(sourceIP)
		if lookupErr == nil {
			if validateAuditText(
				"source host",
				host,
				MaxSourceHostBytes,
				false,
			) == nil {
				attribution.SourceHost = host
			}
		}
	}

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
