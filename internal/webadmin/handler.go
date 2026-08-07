package webadmin

import (
	"io"
	"net/http"
)

func NewHandler(verifier SessionVerifier) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/" {
			http.NotFound(writer, request)
			return
		}

		switch request.Method {
		case http.MethodGet, http.MethodHead:
		default:
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(
				writer,
				"Method not allowed.",
				http.StatusMethodNotAllowed,
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

		_, _ = io.WriteString(writer, landingPage)
	})

	return RequireAdmin(verifier, mux)
}

const landingPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AAMM-NG</title>
</head>
<body>
<main>
<h1>AREDN Alert Message Manager</h1>
<p>AAMM-NG management interface.</p>
</main>
</body>
</html>
`
