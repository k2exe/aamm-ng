package webadmin

import (
	"net/http"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func handleAlertConvert(
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

	_, err := alerts.Convert(
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
		"/",
		http.StatusSeeOther,
	)
}
