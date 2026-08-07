package webadmin

import (
	"errors"
	"net/http"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

type deletePageData struct {
	Target   string
	Kind     string
	Size     int64
	BasePath string
}

func handleDeleteConfirmation(
	writer http.ResponseWriter,
	request *http.Request,
	alerts AlertManager,
	target alerttarget.Target,
) {
	entry, err := alerts.Read(
		request.Context(),
		target.String(),
	)
	if err != nil {
		handleDeleteReadError(
			writer,
			request,
			err,
		)
		return
	}

	writer.Header().Set(
		"Content-Type",
		"text/html; charset=utf-8",
	)
	writer.WriteHeader(http.StatusOK)

	if request.Method == http.MethodHead {
		return
	}

	_ = deleteTemplate.Execute(
		writer,
		deletePageData{
			Target:   entry.Target,
			Kind:     entry.Kind,
			Size:     entry.Size,
			BasePath: requestBasePath(request),
		},
	)
}

func handleAlertDelete(
	writer http.ResponseWriter,
	request *http.Request,
	alerts AlertManager,
	target alerttarget.Target,
) {
	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		maxMutationBodyBytes,
	)

	if err := request.ParseForm(); err != nil {
		invalidDeleteConfirmation(writer)
		return
	}

	confirmations, ok := request.PostForm["confirm"]
	if !ok ||
		len(confirmations) != 1 ||
		len(request.PostForm) != 1 ||
		confirmations[0] != target.String() {
		invalidDeleteConfirmation(writer)
		return
	}

	_, err := alerts.Delete(
		request.Context(),
		target.String(),
	)
	if err != nil {
		handleDeleteError(
			writer,
			request,
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

func handleDeleteReadError(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
) {
	var remoteErr *localcontrol.RemoteError

	if errors.As(err, &remoteErr) &&
		remoteErr.Code == localcontrol.ErrorNotFound {
		http.NotFound(writer, request)
		return
	}

	managementUnavailable(writer)
}

func handleDeleteError(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
) {
	if errors.Is(err, localcontrol.ErrInvalidRequest) {
		invalidDeleteConfirmation(writer)
		return
	}

	var remoteErr *localcontrol.RemoteError
	if !errors.As(err, &remoteErr) {
		managementUnavailable(writer)
		return
	}

	switch remoteErr.Code {
	case localcontrol.ErrorNotFound:
		http.NotFound(writer, request)

	case localcontrol.ErrorSourceChanged:
		http.Error(
			writer,
			"Alert changed and cannot be deleted safely.",
			http.StatusConflict,
		)

	default:
		managementUnavailable(writer)
	}
}

func invalidDeleteConfirmation(
	writer http.ResponseWriter,
) {
	http.Error(
		writer,
		"Invalid delete confirmation.",
		http.StatusBadRequest,
	)
}
