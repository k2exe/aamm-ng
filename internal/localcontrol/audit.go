package localcontrol

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func writeRejectedMutationAudit(
	writer io.Writer,
	timestamp time.Time,
	request Request,
	response Response,
) {
	if writer == nil || !isAudited(request.Operation) {
		return
	}

	safeRequest := Request{
		Operation: request.Operation,
	}

	if target, err := alerttarget.Parse(request.Target); err == nil {
		safeRequest.Target = target.String()
	}

	// A rejected portal request may be malformed. Keep only a bounded name
	// and a valid source address. Never copy the password.
	if request.Portal != nil {
		safePortal := PortalRequest{}

		if request.Portal.Name != "" &&
			len(request.Portal.Name) <= maxPortalNameBytes {
			safePortal.Name = request.Portal.Name
		}

		if address, err := netip.ParseAddr(
			request.Portal.SourceIP,
		); err == nil {
			safePortal.SourceIP = address.Unmap().String()
		}

		safeRequest.Portal = &safePortal
	}

	if request.Audit != nil &&
		validateMutationAudit(*request.Audit) == nil {
		audit := *request.Audit
		safeRequest.Audit = &audit
	}

	writeMutationAudit(
		writer,
		timestamp,
		safeRequest,
		response,
	)
}

func writeMutationAudit(
	writer io.Writer,
	timestamp time.Time,
	request Request,
	response Response,
) {
	if writer == nil || !isAudited(request.Operation) {
		return
	}

	outcome := "success"
	errorCode := ""
	warningCode := ""

	if !response.OK {
		if request.Operation == OperationSettingsReplace &&
			response.Error != nil &&
			response.Error.Code == ErrorSettingsDurabilityUncertain {
			outcome = "applied_with_warning"
			warningCode = response.Error.Code
		} else {
			outcome = "failure"

			if response.Error != nil {
				errorCode = response.Error.Code
			}
		}
	}

	_, _ = fmt.Fprintf(
		writer,
		"aamm-ng audit timestamp=%s",
		timestamp.UTC().Format(time.RFC3339Nano),
	)

	// A login has no authenticated identity yet. Record the name that was
	// tried and the source address. The password is never recorded.
	if request.Operation == OperationPortalLogin &&
		request.Portal != nil {
		_, _ = fmt.Fprintf(
			writer,
			" auth_node=%s auth_method=%s source_ip=%s",
			strconv.Quote(request.Portal.Name),
			strconv.Quote(AuthMethodPortal),
			strconv.Quote(request.Portal.SourceIP),
		)
	}

	if request.Audit != nil {
		_, _ = fmt.Fprintf(
			writer,
			" auth_node=%s auth_role=%s source_ip=%s",
			strconv.Quote(request.Audit.AuthNode),
			strconv.Quote(request.Audit.AuthRole),
			strconv.Quote(request.Audit.SourceIP),
		)

		if request.Audit.AuthMethod != "" {
			_, _ = fmt.Fprintf(
				writer,
				" auth_method=%s",
				strconv.Quote(request.Audit.AuthMethod),
			)
		}

		if request.Audit.SourceNode != "" {
			_, _ = fmt.Fprintf(
				writer,
				" source_node=%s",
				strconv.Quote(request.Audit.SourceNode),
			)
		}

		if request.Audit.SourceHost != "" {
			_, _ = fmt.Fprintf(
				writer,
				" source_host=%s",
				strconv.Quote(request.Audit.SourceHost),
			)
		}
	}

	_, _ = fmt.Fprintf(
		writer,
		" operation=%s target=%s outcome=%s",
		strconv.Quote(string(request.Operation)),
		strconv.Quote(auditTarget(request)),
		strconv.Quote(outcome),
	)

	if errorCode != "" {
		_, _ = fmt.Fprintf(
			writer,
			" error_code=%s",
			strconv.Quote(errorCode),
		)
	}

	if warningCode != "" {
		_, _ = fmt.Fprintf(
			writer,
			" warning_code=%s",
			strconv.Quote(warningCode),
		)
	}

	_, _ = fmt.Fprintln(writer)
}

func isMutation(operation Operation) bool {
	switch operation {
	case OperationCreate,
		OperationWrite,
		OperationConvert,
		OperationDelete,
		OperationSettingsReplace,
		OperationPortalUserCreate,
		OperationPortalUserSetPassword,
		OperationPortalUserSetRole,
		OperationPortalUserSetDisabled,
		OperationPortalUserDelete:
		return true

	default:
		return false
	}
}

// isAudited reports whether an operation is written to the audit log. This
// is every mutation, and every portal login attempt.
func isAudited(operation Operation) bool {
	return isMutation(operation) ||
		operation == OperationPortalLogin
}

// auditTarget is the target shown in an audit line. For a user operation it
// is the user name.
func auditTarget(request Request) string {
	if request.Portal != nil && request.Portal.Name != "" {
		return request.Portal.Name
	}

	return request.Target
}
