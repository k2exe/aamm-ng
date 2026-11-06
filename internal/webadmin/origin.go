package webadmin

import http "github.com/k2exe/aamm-ng/internal/minihttp"

func sameOrigin(request *http.Request) bool {
	if request == nil {
		return false
	}

	origin := request.Header.Get("Origin")
	if origin == "" {
		return false
	}

	// AAMM-NG only ever receives plain HTTP from the loopback CGI bridge.
	expected := "http://" + request.Host

	return origin == expected
}

func forbidden(writer http.ResponseWriter) {
	http.Error(
		writer,
		"Forbidden.",
		http.StatusForbidden,
	)
}
