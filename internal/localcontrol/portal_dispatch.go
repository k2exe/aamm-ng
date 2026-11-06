package localcontrol

import (
	"errors"
	"time"

	"github.com/k2exe/aamm-ng/internal/portalusers"
)

// UserStore is the portal user store the daemon uses.
type UserStore interface {
	List() []portalusers.User
	Create(name string, role portalusers.Role, password string) error
	SetPassword(name string, password string) error
	SetRole(name string, role portalusers.Role) error
	SetDisabled(name string, disabled bool) error
	Delete(name string) error
	Verify(name string, password string) (portalusers.User, error)
}

// PortalUserResult is a user in a response. It never holds a hash.
type PortalUserResult struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
	Created  string `json:"created"`
}

// PortalUsersResult is the response of portal_users_list.
type PortalUsersResult struct {
	Users []PortalUserResult `json:"users"`
}

// PortalLoginResult is the response of a valid portal_login.
type PortalLoginResult struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// PortalUserChangeResult is the response of a user change.
type PortalUserChangeResult struct {
	Name string `json:"name"`
}

// authorize decides whether the caller may run the operation.
//
// The daemon checks this itself and does not trust the web process to do it:
//
//   - list, read and the login check need no identity.
//   - create, write, convert and delete need an AREDN administrator or a
//     portal editor. A portal viewer can never change an alert.
//   - settings changes and every user operation need the AREDN
//     administrator. A portal user can never reach them.
func authorize(request Request) *Response {
	forbidden := Failure(
		ErrorForbidden,
		"this identity may not run this operation",
	)

	switch request.Operation {
	case OperationList,
		OperationRead,
		OperationSettingsRead,
		OperationPortalUsersList,
		OperationPortalLogin:
		return nil

	case OperationCreate,
		OperationWrite,
		OperationConvert,
		OperationDelete:
		if request.Audit == nil {
			return &forbidden
		}

		switch {
		case isAREDNAdministrator(request.Audit):
			return nil

		case request.Audit.AuthMethod == AuthMethodPortal &&
			request.Audit.AuthRole == RoleEditor:
			return nil
		}

		return &forbidden

	case OperationSettingsReplace,
		OperationPortalUserCreate,
		OperationPortalUserSetPassword,
		OperationPortalUserSetRole,
		OperationPortalUserSetDisabled,
		OperationPortalUserDelete:
		if request.Audit != nil &&
			isAREDNAdministrator(request.Audit) {
			return nil
		}

		return &forbidden

	default:
		// Deny by default: a new operation must be given a rule above.
		return &forbidden
	}
}

// authorizeAttributed enforces the role rules when a request carries an
// identity. A request without one has already passed DecodeRequest, which
// requires an identity for every change. DispatchFull checks strictly.
func authorizeAttributed(request Request) *Response {
	if request.Audit == nil {
		return nil
	}

	return authorize(request)
}

func isAREDNAdministrator(audit *MutationAudit) bool {
	if audit == nil {
		return false
	}

	return (audit.AuthMethod == "" ||
		audit.AuthMethod == AuthMethodAREDN) &&
		audit.AuthRole == RoleAdmin
}

// DispatchFull runs a request with alert, settings and portal support.
func DispatchFull(
	store Store,
	settings SettingsStore,
	users UserStore,
	request Request,
) Response {
	if response := authorize(request); response != nil {
		return *response
	}

	switch request.Operation {
	case OperationSettingsRead, OperationSettingsReplace:
		if settings == nil {
			return responseForError(ErrUnknownOperation)
		}

		return DispatchWithSettings(store, settings, request)

	case OperationPortalUsersList,
		OperationPortalLogin,
		OperationPortalUserCreate,
		OperationPortalUserSetPassword,
		OperationPortalUserSetRole,
		OperationPortalUserSetDisabled,
		OperationPortalUserDelete:
		if users == nil {
			return Failure(
				ErrorPortalUnavailable,
				"the multi-user portal is not available",
			)
		}

		return dispatchPortal(users, request)

	default:
		return Dispatch(store, request)
	}
}

func dispatchPortal(users UserStore, request Request) Response {
	switch request.Operation {
	case OperationPortalUsersList:
		list := users.List()
		result := PortalUsersResult{
			Users: make([]PortalUserResult, 0, len(list)),
		}

		for _, user := range list {
			created := ""
			if !user.Created.IsZero() {
				created = user.Created.UTC().Format(time.RFC3339)
			}

			result.Users = append(result.Users, PortalUserResult{
				Name:     user.Name,
				Role:     string(user.Role),
				Disabled: user.Disabled,
				Created:  created,
			})
		}

		return Success(result)

	case OperationPortalLogin:
		user, err := users.Verify(
			request.Portal.Name,
			request.Portal.Password,
		)
		if err != nil {
			return responseForUserError(err)
		}

		return Success(PortalLoginResult{
			Name: user.Name,
			Role: string(user.Role),
		})

	case OperationPortalUserCreate:
		err := users.Create(
			request.Portal.Name,
			portalusers.Role(request.Portal.Role),
			request.Portal.Password,
		)

		return userChangeResponse(request.Portal.Name, err)

	case OperationPortalUserSetPassword:
		err := users.SetPassword(
			request.Portal.Name,
			request.Portal.Password,
		)

		return userChangeResponse(request.Portal.Name, err)

	case OperationPortalUserSetRole:
		err := users.SetRole(
			request.Portal.Name,
			portalusers.Role(request.Portal.Role),
		)

		return userChangeResponse(request.Portal.Name, err)

	case OperationPortalUserSetDisabled:
		err := users.SetDisabled(
			request.Portal.Name,
			*request.Portal.Disabled,
		)

		return userChangeResponse(request.Portal.Name, err)

	case OperationPortalUserDelete:
		err := users.Delete(request.Portal.Name)

		return userChangeResponse(request.Portal.Name, err)

	default:
		return responseForError(ErrUnknownOperation)
	}
}

func userChangeResponse(name string, err error) Response {
	if err != nil &&
		!errors.Is(err, portalusers.ErrDurabilityUncertain) {
		return responseForUserError(err)
	}

	if err != nil {
		return Failure(
			ErrorUserDurability,
			"user change applied; durability is uncertain",
		)
	}

	return Success(PortalUserChangeResult{Name: name})
}

// responseForUserError maps a user store error to a response. The messages
// are fixed text: they never repeat a name or a password.
func responseForUserError(err error) Response {
	switch {
	case errors.Is(err, portalusers.ErrInvalidCredentials):
		return Failure(
			ErrorInvalidCredentials,
			"invalid user name or password",
		)

	case errors.Is(err, portalusers.ErrUserExists):
		return Failure(ErrorUserExists, "user already exists")

	case errors.Is(err, portalusers.ErrUserNotFound):
		return Failure(ErrorUserNotFound, "user not found")

	case errors.Is(err, portalusers.ErrTooManyUsers):
		return Failure(ErrorTooManyUsers, "too many users")

	case errors.Is(err, portalusers.ErrInvalidName),
		errors.Is(err, portalusers.ErrInvalidRole),
		errors.Is(err, portalusers.ErrInvalidPassword):
		return Failure(ErrorInvalidUser, "invalid user details")

	default:
		return Failure(ErrorInternal, "could not change users")
	}
}
