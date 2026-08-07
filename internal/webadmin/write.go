package webadmin

import (
	"errors"
	"net/http"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

const maxMutationBodyBytes int64 = 16 * 1024

func handleAlertWrite(
	writer http.ResponseWriter,
	request *http.Request,
	alerts AlertManager,
	target alerttarget.Target,
) {
	message, ok := mutationMessage(
		writer,
		request,
	)
	if !ok {
		return
	}

	_, err := alerts.Write(
		request.Context(),
		target.String(),
		message,
	)
	if err != nil {
		handleMutationError(
			writer,
			request,
			err,
		)
		return
	}

	http.Redirect(
		writer,
		request,
		"/alerts/"+target.String(),
		http.StatusSeeOther,
	)
}

func mutationMessage(
	writer http.ResponseWriter,
	request *http.Request,
) (string, bool) {
	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		maxMutationBodyBytes,
	)

	if err := request.ParseForm(); err != nil {
		invalidAlertUpdate(writer)
		return "", false
	}

	messages, ok := request.PostForm["message"]
	if !ok ||
		len(messages) != 1 ||
		len(request.PostForm) != 1 {
		invalidAlertUpdate(writer)
		return "", false
	}

	return messages[0], true
}

func handleMutationError(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
) {
	if errors.Is(err, localcontrol.ErrInvalidRequest) {
		invalidAlertUpdate(writer)
		return
	}

	var remoteErr *localcontrol.RemoteError
	if !errors.As(err, &remoteErr) {
		managementUnavailable(writer)
		return
	}

	switch remoteErr.Code {
	case localcontrol.ErrorInvalidTarget,
		localcontrol.ErrorInvalidMessage:
		invalidAlertUpdate(writer)

	case localcontrol.ErrorNotFound:
		http.NotFound(writer, request)

	case localcontrol.ErrorLegacyConflict,
		localcontrol.ErrorOversizedConflict,
		localcontrol.ErrorManagedConflict,
		localcontrol.ErrorSourceChanged:
		http.Error(
			writer,
			"Alert changed and cannot be updated safely.",
			http.StatusConflict,
		)

	default:
		managementUnavailable(writer)
	}
}

func invalidAlertUpdate(writer http.ResponseWriter) {
	http.Error(
		writer,
		"Invalid alert update.",
		http.StatusBadRequest,
	)
}
