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

type AlertManager interface {
	List(context.Context) (localcontrol.ListResult, error)
	Read(context.Context, string) (localcontrol.EntryResult, error)
	Write(context.Context, string, string) (localcontrol.WriteResult, error)
	Convert(context.Context, string, string) (localcontrol.ConvertResult, error)
	Delete(context.Context, string) (localcontrol.DeleteResult, error)
}

func NewHandler(
	verifier SessionVerifier,
	alerts AlertManager,
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
				BasePath: requestBasePath(request),
				Entries:  listing.Entries,
				Issues:   listing.Issues,
			},
		)
	})

	mux.HandleFunc("/alerts/{target}/delete", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.Method {
		case http.MethodGet, http.MethodHead:

		case http.MethodPost:
			if !sameOrigin(request) {
				forbidden(writer)
				return
			}

		default:
			writer.Header().Set(
				"Allow",
				"GET, HEAD, POST",
			)
			http.Error(
				writer,
				"Method not allowed.",
				http.StatusMethodNotAllowed,
			)
			return
		}

		target, err := alerttarget.Parse(
			request.PathValue("target"),
		)
		if err != nil {
			http.NotFound(writer, request)
			return
		}

		if alerts == nil {
			managementUnavailable(writer)
			return
		}

		if request.Method == http.MethodPost {
			handleAlertDelete(
				writer,
				request,
				alerts,
				target,
			)
			return
		}

		handleDeleteConfirmation(
			writer,
			request,
			alerts,
			target,
		)
	})

	mux.HandleFunc("/alerts/{target}/convert", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", "POST")
			http.Error(
				writer,
				"Method not allowed.",
				http.StatusMethodNotAllowed,
			)
			return
		}

		if !sameOrigin(request) {
			forbidden(writer)
			return
		}

		target, err := alerttarget.Parse(
			request.PathValue("target"),
		)
		if err != nil {
			http.NotFound(writer, request)
			return
		}

		if alerts == nil {
			managementUnavailable(writer)
			return
		}

		handleAlertConvert(
			writer,
			request,
			alerts,
			target,
		)
	})

	mux.HandleFunc("/alerts/", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch request.Method {
		case http.MethodGet, http.MethodHead:

		case http.MethodPost:
			if !sameOrigin(request) {
				forbidden(writer)
				return
			}

		default:
			writer.Header().Set(
				"Allow",
				"GET, HEAD, POST",
			)
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

		if request.Method == http.MethodPost {
			handleAlertWrite(
				writer,
				request,
				alerts,
				target,
			)
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

		_ = detailTemplate.Execute(
			writer,
			detailPageData{
				EntryResult: entry,
				BasePath:    requestBasePath(request),
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
	BasePath string
	Entries  []localcontrol.EntryResult
	Issues   []localcontrol.IssueResult
}

type detailPageData struct {
	localcontrol.EntryResult
	BasePath string
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
<h1>AREDN Alert Message Manager NG</h1>

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
<td><a href="{{$.BasePath}}/alerts/{{.Target}}">{{.Target}}</a></td>
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

var deleteTemplate = template.Must(
	template.New("delete").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Delete {{.Target}} - AAMM-NG</title>
</head>
<body>
<main>
<p><a href="{{.BasePath}}/alerts/{{.Target}}">Back to alert</a></p>

<h1>Delete alert: {{.Target}}</h1>

<p>
This will remove the alert from the node.
AAMM-NG will create a backup before deletion.
</p>

<dl>
<dt>Type</dt>
<dd>{{.Kind}}</dd>
<dt>Size</dt>
<dd>{{.Size}} bytes</dd>
</dl>

<form method="post" action="{{.BasePath}}/alerts/{{.Target}}/delete">
<label for="confirm">
Type <strong>{{.Target}}</strong> to confirm deletion:
</label><br>
<input
	id="confirm"
	name="confirm"
	type="text"
	autocomplete="off"
	required
>
<button type="submit">Delete alert</button>
</form>
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
<p><a href="{{.BasePath}}/">Back to alerts</a></p>

<h1>Alert: {{.Target}}</h1>

<dl>
<dt>Type</dt>
<dd>{{.Kind}}</dd>
<dt>Size</dt>
<dd>{{.Size}} bytes</dd>
</dl>

{{if eq .Kind "managed"}}
<h2>Message</h2>
<form method="post" action="{{.BasePath}}/alerts/{{.Target}}">
<label for="message">Alert message</label><br>
<textarea id="message" name="message" rows="8" cols="72" required>{{.Message}}</textarea>
<p>Maximum 4096 bytes.</p>
<button type="submit">Save alert</button>
</form>
{{else if eq .Kind "legacy"}}
<h2>Legacy source</h2>
<p>This legacy alert must be converted before AAMM-NG can manage it.</p>
<pre>{{.LegacySource}}</pre>

<h2>Convert to managed alert</h2>
<p>The original legacy alert will be backed up before conversion.</p>
<form method="post" action="{{.BasePath}}/alerts/{{.Target}}/convert">
<label for="message">Replacement alert message</label><br>
<textarea id="message" name="message" rows="8" cols="72" required></textarea>
<p>Maximum 4096 bytes.</p>
<button type="submit">Convert alert</button>
</form>
{{else if eq .Kind "oversized"}}
<p>Oversized alert — manual review required.</p>
{{else}}
<p>Unknown alert type.</p>
{{end}}

<p><a href="{{.BasePath}}/alerts/{{.Target}}/delete">Delete alert</a></p>
</main>
</body>
</html>
`),
)
