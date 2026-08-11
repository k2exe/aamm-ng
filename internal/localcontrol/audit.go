package localcontrol

import (
	"fmt"
	"io"
	"strconv"
	"time"
)

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

	if !response.OK {
		outcome = "failure"

		if response.Error != nil {
			errorCode = response.Error.Code
		}
	}

	_, _ = fmt.Fprintf(
		writer,
		"aamm-ng audit timestamp=%s actor=%s operation=%s target=%s outcome=%s",
		timestamp.UTC().Format(time.RFC3339Nano),
		strconv.Quote(request.Actor),
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

	_, _ = fmt.Fprintln(writer)
}

func isMutation(operation Operation) bool {
	switch operation {
	case OperationCreate,
		OperationWrite,
		OperationConvert,
		OperationDelete:
		return true

	default:
		return false
	}
}
