package webadmin

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

type AlertReader interface {
	List(context.Context) (localcontrol.ListResult, error)
	Read(context.Context, string) (localcontrol.EntryResult, error)
}

func NewHandler(
	verifier SessionVerifier,
	alerts AlertReader,
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

		if alerts == nil {
			managementUnavailable(writer)
			return
		}

		listing, err := alerts.List(request.Context())
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

	mux.HandleFunc("/alerts/", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
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

		targetValue := strings.TrimPrefix(
			request.URL.Path,
			"/alerts/",
		)

		if targetValue == "" ||
			strings.Contains(targetValue, "/") {
			http.NotFound(writer, request)
			return
		}

		target, err := alerttarget.Parse(targetValue)
		if err != nil {
			http.NotFound(writer, request)
			return
		}

		if alerts == nil {
			managementUnavailable(writer)
			return
		}

		entry, err := alerts.Read(
			request.Context(),
			target.String(),
		)
		if err != nil {
			var remoteErr *localcontrol.RemoteError

			if errors.As(err, &remoteErr) &&
				remoteErr.Code == localcontrol.ErrorNotFound {
				http.NotFound(writer, request)
				return
			}

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

		_ = detailTemplate.Execute(writer, entry)
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
<td><a href="/alerts/{{.Target}}">{{.Target}}</a></td>
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

var detailTemplate = template.Must(
	template.New("detail").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Target}} - AAMM-NG</title>
</head>
<body>
<main>
<p><a href="/">Back to alerts</a></p>

<h1>Alert: {{.Target}}</h1>

<dl>
<dt>Type</dt>
<dd>{{.Kind}}</dd>
<dt>Size</dt>
<dd>{{.Size}} bytes</dd>
</dl>

{{if eq .Kind "managed"}}
<h2>Message</h2>
<pre>{{.Message}}</pre>
{{else if eq .Kind "legacy"}}
<h2>Legacy source</h2>
<p>This legacy alert must be converted before AAMM-NG can manage it.</p>
<pre>{{.LegacySource}}</pre>
{{else if eq .Kind "oversized"}}
<p>Oversized alert — manual review required.</p>
{{else}}
<p>Unknown alert type.</p>
{{end}}
</main>
</body>
</html>
`),
)
