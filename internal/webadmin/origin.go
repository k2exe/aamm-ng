package webadmin

import "net/http"

func sameOrigin(request *http.Request) bool {
	if request == nil {
		return false
	}

	origin := request.Header.Get("Origin")
	if origin == "" {
		return false
	}

	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}

	expected := scheme + "://" + request.Host

	return origin == expected
}

func forbidden(writer http.ResponseWriter) {
	http.Error(
		writer,
		"Forbidden.",
		http.StatusForbidden,
	)
}
