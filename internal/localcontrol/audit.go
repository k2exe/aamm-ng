package localcontrol

import (
	"fmt"
	"io"
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
	if writer == nil || !isMutation(request.Operation) {
		return
	}

	safeRequest := Request{
		Operation: request.Operation,
	}

	if target, err := alerttarget.Parse(request.Target); err == nil {
		safeRequest.Target = target.String()
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
	if writer == nil || !isMutation(request.Operation) {
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

	if request.Audit != nil {
		_, _ = fmt.Fprintf(
			writer,
			" auth_node=%s auth_role=%s source_ip=%s",
			strconv.Quote(request.Audit.AuthNode),
			strconv.Quote(request.Audit.AuthRole),
			strconv.Quote(request.Audit.SourceIP),
		)

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
		strconv.Quote(request.Target),
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
		OperationSettingsReplace:
		return true

	default:
		return false
	}
}
