package localcontrol

import (
	"context"
	"fmt"
	"net/netip"
)

// PortalUsersList returns the portal users. It never returns a hash.
func (client *Client) PortalUsersList(
	ctx context.Context,
) (PortalUsersResult, error) {
	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationPortalUsersList,
		},
	)
	if err != nil {
		return PortalUsersResult{}, err
	}

	return decodeTypedResult[PortalUsersResult](response)
}

// PortalLogin checks a portal login. The source address is recorded in the
// audit log with the name that was tried, never the password.
func (client *Client) PortalLogin(
	ctx context.Context,
	name string,
	password string,
	sourceIP string,
) (PortalLoginResult, error) {
	address, err := netip.ParseAddr(sourceIP)
	if err != nil {
		return PortalLoginResult{}, fmt.Errorf(
			"%w: invalid source address",
			ErrInvalidRequest,
		)
	}

	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationPortalLogin,
			Portal: &PortalRequest{
				Name:     name,
				Password: password,
				SourceIP: address.Unmap().String(),
			},
		},
	)
	if err != nil {
		return PortalLoginResult{}, err
	}

	return decodeTypedResult[PortalLoginResult](response)
}

func (client *Client) portalUserChange(
	ctx context.Context,
	operation Operation,
	portal PortalRequest,
) error {
	audit, err := client.mutationAuditFromContext(ctx)
	if err != nil {
		return err
	}

	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: operation,
			Portal:    &portal,
			Audit:     &audit,
		},
	)
	if err != nil {
		return err
	}

	_, err = decodeTypedResult[PortalUserChangeResult](response)

	return err
}

// PortalUserCreate adds a portal user. The context must carry the AREDN
// administrator identity.
func (client *Client) PortalUserCreate(
	ctx context.Context,
	name string,
	role string,
	password string,
) error {
	return client.portalUserChange(
		ctx,
		OperationPortalUserCreate,
		PortalRequest{Name: name, Role: role, Password: password},
	)
}

// PortalUserSetPassword replaces a portal user's password.
func (client *Client) PortalUserSetPassword(
	ctx context.Context,
	name string,
	password string,
) error {
	return client.portalUserChange(
		ctx,
		OperationPortalUserSetPassword,
		PortalRequest{Name: name, Password: password},
	)
}

// PortalUserSetRole changes a portal user's role.
func (client *Client) PortalUserSetRole(
	ctx context.Context,
	name string,
	role string,
) error {
	return client.portalUserChange(
		ctx,
		OperationPortalUserSetRole,
		PortalRequest{Name: name, Role: role},
	)
}

// PortalUserSetDisabled disables or enables a portal user.
func (client *Client) PortalUserSetDisabled(
	ctx context.Context,
	name string,
	disabled bool,
) error {
	return client.portalUserChange(
		ctx,
		OperationPortalUserSetDisabled,
		PortalRequest{Name: name, Disabled: &disabled},
	)
}

// PortalUserDelete removes a portal user.
func (client *Client) PortalUserDelete(
	ctx context.Context,
	name string,
) error {
	return client.portalUserChange(
		ctx,
		OperationPortalUserDelete,
		PortalRequest{Name: name},
	)
}
