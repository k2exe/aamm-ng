package localcontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

const (
	ProtocolVersion    = 2
	MaxRequestBytes    = 16 * 1024
	MaxAuthNodeBytes   = 128
	MaxSourceNodeBytes = 255
	MaxSourceHostBytes = 255
)

type Operation string

const (
	OperationList            Operation = "list"
	OperationRead            Operation = "read"
	OperationCreate          Operation = "create"
	OperationWrite           Operation = "write"
	OperationConvert         Operation = "convert"
	OperationDelete          Operation = "delete"
	OperationSettingsRead    Operation = "settings_read"
	OperationSettingsReplace Operation = "settings_replace"

	// Portal operations. The user operations change the user store and are
	// for the AREDN administrator only. Login checks a portal login.
	OperationPortalUsersList       Operation = "portal_users_list"
	OperationPortalUserCreate      Operation = "portal_user_create"
	OperationPortalUserSetPassword Operation = "portal_user_set_password"
	OperationPortalUserSetRole     Operation = "portal_user_set_role"
	OperationPortalUserSetDisabled Operation = "portal_user_set_disabled"
	OperationPortalUserDelete      Operation = "portal_user_delete"
	OperationPortalLogin           Operation = "portal_login"
)

var (
	ErrRequestTooLarge    = errors.New("control request exceeds size limit")
	ErrInvalidRequest     = errors.New("invalid control request")
	ErrUnsupportedVersion = errors.New("unsupported control protocol version")
	ErrUnknownOperation   = errors.New("unknown control operation")
)

// Authentication methods in MutationAudit.AuthMethod. An empty method
// means the AREDN administrator, as before.
const (
	AuthMethodAREDN  = "aredn"
	AuthMethodPortal = "portal"
)

// Roles in MutationAudit.AuthRole.
const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

type MutationAudit struct {
	AuthNode   string `json:"auth_node,omitempty"`
	AuthRole   string `json:"auth_role,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	SourceNode string `json:"source_node,omitempty"`
	SourceHost string `json:"source_host,omitempty"`
}

// PortalRequest carries the fields of a portal operation. Password is a
// secret: never log it, never put it in an audit line.
type PortalRequest struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
	Disabled *bool  `json:"disabled,omitempty"`
	SourceIP string `json:"source_ip,omitempty"`
}

type Request struct {
	Version   int               `json:"version"`
	Operation Operation         `json:"operation"`
	Target    string            `json:"target,omitempty"`
	Message   string            `json:"message,omitempty"`
	Settings  *appconfig.Config `json:"settings,omitempty"`
	Portal    *PortalRequest    `json:"portal,omitempty"`
	Audit     *MutationAudit    `json:"audit,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

func DecodeRequest(data []byte) (Request, error) {
	if len(data) > MaxRequestBytes {
		return Request{}, ErrRequestTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var request Request

	if err := decoder.Decode(&request); err != nil {
		return request, fmt.Errorf(
			"%w: %v",
			ErrInvalidRequest,
			err,
		)
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return request, fmt.Errorf(
				"%w: multiple JSON values",
				ErrInvalidRequest,
			)
		}

		return request, fmt.Errorf(
			"%w: trailing data: %v",
			ErrInvalidRequest,
			err,
		)
	}

	if err := validateRequest(request); err != nil {
		return request, err
	}

	return request, nil
}

func validateRequest(request Request) error {
	if request.Version != ProtocolVersion {
		return fmt.Errorf(
			"%w: %d",
			ErrUnsupportedVersion,
			request.Version,
		)
	}

	switch request.Operation {
	case OperationList:
		if request.Target != "" ||
			request.Message != "" ||
			request.Settings != nil ||
			request.Portal != nil ||
			request.Audit != nil {
			return fmt.Errorf(
				"%w: list accepts no target, message, settings, or audit attribution",
				ErrInvalidRequest,
			)
		}

	case OperationRead:
		if request.Target == "" {
			return fmt.Errorf(
				"%w: read requires target",
				ErrInvalidRequest,
			)
		}

		if request.Message != "" ||
			request.Settings != nil ||
			request.Portal != nil ||
			request.Audit != nil {
			return fmt.Errorf(
				"%w: read accepts no message, settings, or audit attribution",
				ErrInvalidRequest,
			)
		}

	case OperationDelete:
		if request.Target == "" {
			return fmt.Errorf(
				"%w: delete requires target",
				ErrInvalidRequest,
			)
		}

		if request.Message != "" ||
			request.Settings != nil ||
			request.Portal != nil {
			return fmt.Errorf(
				"%w: delete accepts no message or settings",
				ErrInvalidRequest,
			)
		}

		if err := validateRequestAudit(request.Audit); err != nil {
			return err
		}

	case OperationCreate, OperationWrite, OperationConvert:
		if request.Target == "" {
			return fmt.Errorf(
				"%w: %s requires target",
				ErrInvalidRequest,
				request.Operation,
			)
		}

		if request.Message == "" {
			return fmt.Errorf(
				"%w: %s requires message",
				ErrInvalidRequest,
				request.Operation,
			)
		}

		if request.Settings != nil || request.Portal != nil {
			return fmt.Errorf(
				"%w: %s accepts no settings",
				ErrInvalidRequest,
				request.Operation,
			)
		}

		if err := validateRequestAudit(request.Audit); err != nil {
			return err
		}

	case OperationSettingsRead:
		if request.Target != "" ||
			request.Message != "" ||
			request.Settings != nil ||
			request.Portal != nil ||
			request.Audit != nil {
			return fmt.Errorf(
				"%w: settings_read accepts no target, message, settings, or audit attribution",
				ErrInvalidRequest,
			)
		}

	case OperationSettingsReplace:
		if request.Target != "" ||
			request.Message != "" ||
			request.Portal != nil {
			return fmt.Errorf(
				"%w: settings_replace accepts no target or message",
				ErrInvalidRequest,
			)
		}

		if request.Settings == nil {
			return fmt.Errorf(
				"%w: settings_replace requires settings",
				ErrInvalidRequest,
			)
		}

		if err := validateRequestAudit(request.Audit); err != nil {
			return err
		}

	case OperationPortalUsersList:
		if request.Target != "" ||
			request.Message != "" ||
			request.Settings != nil ||
			request.Portal != nil ||
			request.Audit != nil {
			return fmt.Errorf(
				"%w: portal_users_list accepts no fields",
				ErrInvalidRequest,
			)
		}

	case OperationPortalLogin:
		if request.Target != "" ||
			request.Message != "" ||
			request.Settings != nil ||
			request.Audit != nil {
			return fmt.Errorf(
				"%w: portal_login accepts only portal fields",
				ErrInvalidRequest,
			)
		}

		if err := validatePortalRequest(
			request.Operation,
			request.Portal,
		); err != nil {
			return err
		}

	case OperationPortalUserCreate,
		OperationPortalUserSetPassword,
		OperationPortalUserSetRole,
		OperationPortalUserSetDisabled,
		OperationPortalUserDelete:
		if request.Target != "" ||
			request.Message != "" ||
			request.Settings != nil {
			return fmt.Errorf(
				"%w: %s accepts only portal fields",
				ErrInvalidRequest,
				request.Operation,
			)
		}

		if err := validatePortalRequest(
			request.Operation,
			request.Portal,
		); err != nil {
			return err
		}

		if err := validateRequestAudit(request.Audit); err != nil {
			return err
		}

	default:
		return fmt.Errorf(
			"%w: %q",
			ErrUnknownOperation,
			request.Operation,
		)
	}

	return nil
}

// Limits for portal request fields. The user store applies the real rules.
const (
	maxPortalNameBytes     = 64
	maxPortalPasswordBytes = 256
	maxPortalRoleBytes     = 16
)

func validatePortalRequest(
	operation Operation,
	portal *PortalRequest,
) error {
	invalid := func(reason string) error {
		return fmt.Errorf(
			"%w: %s %s",
			ErrInvalidRequest,
			operation,
			reason,
		)
	}

	if portal == nil {
		return invalid("requires portal fields")
	}

	if portal.Name == "" ||
		len(portal.Name) > maxPortalNameBytes {
		return invalid("requires a name")
	}

	if len(portal.Password) > maxPortalPasswordBytes ||
		len(portal.Role) > maxPortalRoleBytes {
		return invalid("has a field that is too long")
	}

	hasPassword := portal.Password != ""
	hasRole := portal.Role != ""
	hasDisabled := portal.Disabled != nil
	hasSource := portal.SourceIP != ""

	switch operation {
	case OperationPortalLogin:
		if !hasPassword || hasRole || hasDisabled || !hasSource {
			return invalid("requires a name, password and source address only")
		}

		address, err := netip.ParseAddr(portal.SourceIP)
		if err != nil || address.Unmap().String() != portal.SourceIP {
			return invalid("requires a canonical source address")
		}

	case OperationPortalUserCreate:
		if !hasPassword || !hasRole || hasDisabled || hasSource {
			return invalid("requires a name, role and password only")
		}

	case OperationPortalUserSetPassword:
		if !hasPassword || hasRole || hasDisabled || hasSource {
			return invalid("requires a name and password only")
		}

	case OperationPortalUserSetRole:
		if hasPassword || !hasRole || hasDisabled || hasSource {
			return invalid("requires a name and role only")
		}

	case OperationPortalUserSetDisabled:
		if hasPassword || hasRole || !hasDisabled || hasSource {
			return invalid("requires a name and disabled flag only")
		}

	case OperationPortalUserDelete:
		if hasPassword || hasRole || hasDisabled || hasSource {
			return invalid("requires a name only")
		}
	}

	return nil
}

func validateRequestAudit(audit *MutationAudit) error {
	if audit == nil {
		return fmt.Errorf(
			"%w: mutating operation requires audit attribution",
			ErrInvalidRequest,
		)
	}

	return validateMutationAudit(*audit)
}

func validateMutationAudit(audit MutationAudit) error {
	if err := validateAuditText(
		"auth node",
		audit.AuthNode,
		MaxAuthNodeBytes,
		true,
	); err != nil {
		return err
	}

	switch audit.AuthMethod {
	case "", AuthMethodAREDN:
		// The AREDN administrator.
		if audit.AuthRole != RoleAdmin {
			return fmt.Errorf(
				"%w: invalid authenticated role",
				ErrInvalidRequest,
			)
		}

	case AuthMethodPortal:
		// A portal user is an editor or a viewer, never an administrator.
		if audit.AuthRole != RoleEditor &&
			audit.AuthRole != RoleViewer {
			return fmt.Errorf(
				"%w: invalid authenticated role",
				ErrInvalidRequest,
			)
		}

	default:
		return fmt.Errorf(
			"%w: invalid authentication method",
			ErrInvalidRequest,
		)
	}

	address, err := netip.ParseAddr(audit.SourceIP)
	if err != nil {
		return fmt.Errorf(
			"%w: invalid source address",
			ErrInvalidRequest,
		)
	}

	if address.Unmap().String() != audit.SourceIP {
		return fmt.Errorf(
			"%w: source address is not canonical",
			ErrInvalidRequest,
		)
	}

	if err := validateAuditText(
		"source node",
		audit.SourceNode,
		MaxSourceNodeBytes,
		false,
	); err != nil {
		return err
	}

	if err := validateAuditText(
		"source host",
		audit.SourceHost,
		MaxSourceHostBytes,
		false,
	); err != nil {
		return err
	}

	if audit.SourceHost != "" && audit.SourceNode == "" {
		return fmt.Errorf(
			"%w: source host requires source node",
			ErrInvalidRequest,
		)
	}

	return nil
}

func validateAuditText(
	field string,
	value string,
	maxBytes int,
	required bool,
) error {
	if value == "" {
		if required {
			return fmt.Errorf(
				"%w: %s required",
				ErrInvalidRequest,
				field,
			)
		}

		return nil
	}

	if len(value) > maxBytes {
		return fmt.Errorf(
			"%w: %s exceeds %d bytes",
			ErrInvalidRequest,
			field,
			maxBytes,
		)
	}

	if strings.TrimSpace(value) != value {
		return fmt.Errorf(
			"%w: %s contains surrounding whitespace",
			ErrInvalidRequest,
			field,
		)
	}

	for _, value := range value {
		if unicode.IsControl(value) ||
			unicode.In(value, unicode.Cf) {
			return fmt.Errorf(
				"%w: %s contains unsafe characters",
				ErrInvalidRequest,
				field,
			)
		}
	}

	return nil
}

func Success(result any) Response {
	return Response{
		Version: ProtocolVersion,
		OK:      true,
		Result:  result,
	}
}

func Failure(code string, message string) Response {
	return Response{
		Version: ProtocolVersion,
		OK:      false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	}
}
