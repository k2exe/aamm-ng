package webadmin

import (
	"context"
	"html/template"
	"net/http"

	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

type AlertLister interface {
	List(context.Context) (localcontrol.ListResult, error)
}

func NewHandler(
	verifier SessionVerifier,
	lister AlertLister,
) http.Handler {
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

		if lister == nil {
			managementUnavailable(writer)
			return
		}

		listing, err := lister.List(request.Context())
		if err != nil {
			managementUnavailable(writer)
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

		_ = landingTemplate.Execute(
			writer,
			pageData{
				Entries: listing.Entries,
				Issues:  listing.Issues,
			},
		)
	})

	return RequireAdmin(verifier, mux)
}

func managementUnavailable(writer http.ResponseWriter) {
	http.Error(
		writer,
		"AAMM-NG control service unavailable.",
		http.StatusServiceUnavailable,
	)
}

type pageData struct {
	Entries []localcontrol.EntryResult
	Issues  []localcontrol.IssueResult
}

var landingTemplate = template.Must(
	template.New("landing").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AAMM-NG</title>
</head>
<body>
<main>
<h1>AREDN Alert Message Manager</h1>

<h2>Alerts</h2>
{{if .Entries}}
<table>
<thead>
<tr>
<th scope="col">Target</th>
<th scope="col">Type</th>
<th scope="col">Message</th>
<th scope="col">Size</th>
</tr>
</thead>
<tbody>
{{range .Entries}}
<tr>
<td>{{.Target}}</td>
<td>{{.Kind}}</td>
<td>
{{if eq .Kind "managed"}}
{{.Message}}
{{else if eq .Kind "legacy"}}
Legacy alert — conversion required
{{else if eq .Kind "oversized"}}
Oversized alert — manual review required
{{else}}
Unknown alert type
{{end}}
</td>
<td>{{.Size}} bytes</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No alert files found.</p>
{{end}}

{{if .Issues}}
<h2>Inspection issues</h2>
<ul>
{{range .Issues}}
<li>{{.Name}}: {{.Kind}}</li>
{{end}}
</ul>
{{end}}
</main>
</body>
</html>
`),
)
