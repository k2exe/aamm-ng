package webadmin

import (
	"errors"
	"net/http"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

func handleAlertCreate(
	writer http.ResponseWriter,
	request *http.Request,
	alerts AlertManager,
) {
	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		maxMutationBodyBytes,
	)

	if err := request.ParseForm(); err != nil {
		invalidAlertCreate(writer)
		return
	}

	targets, targetOK := request.PostForm["target"]
	messages, messageOK := request.PostForm["message"]

	if !targetOK ||
		!messageOK ||
		len(targets) != 1 ||
		len(messages) != 1 ||
		len(request.PostForm) != 2 {
		invalidAlertCreate(writer)
		return
	}

	target, err := alerttarget.Parse(targets[0])
	if err != nil {
		invalidAlertCreate(writer)
		return
	}

	_, err = alerts.Create(
		request.Context(),
		target.String(),
		messages[0],
	)
	if err != nil {
		handleCreateError(
			writer,
			err,
		)
		return
	}

	http.Redirect(
		writer,
		request,
		"/",
		http.StatusSeeOther,
	)
}

func handleCreateError(
	writer http.ResponseWriter,
	err error,
) {
	if errors.Is(err, localcontrol.ErrInvalidRequest) {
		invalidAlertCreate(writer)
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
		invalidAlertCreate(writer)

	case localcontrol.ErrorAlreadyExists:
		http.Error(
			writer,
			"An alert already exists for that target.",
			http.StatusConflict,
		)

	default:
		managementUnavailable(writer)
	}
}

func invalidAlertCreate(writer http.ResponseWriter) {
	http.Error(
		writer,
		"Invalid new alert.",
		http.StatusBadRequest,
	)
}
