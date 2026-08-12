package webadmin

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/arednnodes"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

type AlertManager interface {
	List(context.Context) (localcontrol.ListResult, error)
	Read(context.Context, string) (localcontrol.EntryResult, error)
	Create(context.Context, string, string) (localcontrol.CreateResult, error)
	Write(context.Context, string, string) (localcontrol.WriteResult, error)
	Convert(context.Context, string, string) (localcontrol.ConvertResult, error)
	Delete(context.Context, string) (localcontrol.DeleteResult, error)
}

type nodeFinder interface {
	LocalNodes(context.Context) ([]string, error)
}

func NewHandler(
	verifier SessionVerifier,
	alerts AlertManager,
) http.Handler {
	return newHandler(
		verifier,
		alerts,
		arednnodes.NewFetcher(),
	)
}

func newHandler(
	verifier SessionVerifier,
	alerts AlertManager,
	nodes nodeFinder,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/local-nodes", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		handleLocalNodes(
			writer,
			request,
			nodes,
		)
	})

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

	mux.HandleFunc("/alerts/new", func(
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

		if alerts == nil {
			managementUnavailable(writer)
			return
		}

		if request.Method == http.MethodPost {
			handleAlertCreate(
				writer,
				request,
				alerts,
			)
			return
		}

		var listing localcontrol.ListResult
		var err error

		if request.Method == http.MethodGet {
			listing, err = alerts.List(request.Context())
			if err != nil {
				managementUnavailable(writer)
				return
			}
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
				NewModal: true,
			},
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

		var listing localcontrol.ListResult

		if request.Method == http.MethodGet {
			listing, err = alerts.List(request.Context())
			if err != nil {
				managementUnavailable(writer)
				return
			}
		}

		writer.Header().Set(
			"Content-Type",
			"text/html; charset=utf-8",
		)
		writer.WriteHeader(http.StatusOK)

		if request.Method == http.MethodHead {
			return
		}

		modalEntry := entry

		_ = landingTemplate.Execute(
			writer,
			pageData{
				BasePath: requestBasePath(request),
				Entries:  listing.Entries,
				Issues:   listing.Issues,
				Modal:    &modalEntry,
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
	BasePath    string
	Entries     []localcontrol.EntryResult
	Issues      []localcontrol.IssueResult
	Modal       *localcontrol.EntryResult
	DeleteModal *localcontrol.EntryResult
	NewModal    bool
}

var landingTemplate = template.Must(
	template.New("landing").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AAMM-NG — Alert Message Manager</title>

<link rel="stylesheet" href="/a/css/theme.css">
<link rel="stylesheet" href="/a/css/user.css">
<link rel="stylesheet" href="/a/css/admin.css">
<link rel="stylesheet" href="/apps/AAMM-NG/aamm-ng.css">
<script src="/apps/AAMM-NG/aamm-ng.js" defer></script>

<link rel="icon" type="image/svg+xml" href="/apps/AAMM-NG/icon.svg">
</head>

<body class="authenticated">

{{if .NewModal}}
<dialog
	id="ctrl-modal"
	data-return-url="{{.BasePath}}/"
>
	<div class="dialog">

		<div>
			<div class="t">Create AAMM-NG Alert</div>
			<div class="s">New alert message</div>
			<hr>
		</div>

		<div>
			<form
				id="aamm-create-form"
				method="post"
				action="{{.BasePath}}/alerts/new"
			>
				<div class="o">Target</div>

				<div
					class="aamm-target-picker"
					data-aamm-node-endpoint="{{.BasePath}}/api/local-nodes"
				>
					<input
						class="aamm-create-target"
						id="target"
						name="target"
						type="text"
						autocomplete="off"
						autofocus
						maxlength="63"
						pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,62}"
						placeholder="all or node-name"
						required
					>

					<button
						type="button"
						data-aamm-find-node
						aria-controls="aamm-node-results"
						aria-expanded="false"
					>
						Find node
					</button>

					<div
						id="aamm-node-results"
						class="aamm-node-results"
						data-aamm-node-results
						role="group"
						aria-label="Local AREDN nodes"
						hidden
					></div>
				</div>

				<div class="m">
					Use <strong>all</strong> for all nodes, enter a node target,
					or use <strong>Find node</strong> to search the local AREDN mesh.
					Letters, numbers, hyphen, and underscore are supported.
				</div>

				<div
					class="m aamm-node-status"
					data-aamm-node-status
					aria-live="polite"
				></div>

				<div class="o">Message</div>

				<textarea
					class="aamm-message-editor"
					id="message"
					name="message"
					required
				></textarea>

				<div class="m">
					Maximum 4096 bytes.
					AAMM-NG will not overwrite an existing alert.
				</div>
			</form>
		</div>

		<div class="ctrl-modal-footer">
			<hr>

			<div class="aamm-modal-actions">
				<button type="button" data-aamm-close>
					Cancel
				</button>

				<button
					id="dialog-done"
					type="submit"
					form="aamm-create-form"
				>
					Create
				</button>
			</div>
		</div>

	</div>
</dialog>
{{end}}

{{with .Modal}}
<dialog
	id="ctrl-modal"
	data-return-url="{{$.BasePath}}/"
>
	<div class="dialog">

		<div>
			<div class="t">Edit AAMM-NG Alert</div>
			<div class="s">{{.Target}}</div>
			<hr>
		</div>

		<div>
			<div class="aamm-modal-meta">
				<div>
					<div class="s">Target</div>
					<div class="t aamm-modal-target">{{.Target}}</div>
				</div>

				<div>
					<div class="s">Status</div>
					<div>
						{{if eq .Kind "managed"}}
						<span class="aamm-kind aamm-managed">Managed</span>
						{{else if eq .Kind "legacy"}}
						<span class="aamm-kind aamm-existing">Existing</span>
						{{else if eq .Kind "oversized"}}
						<span class="aamm-kind aamm-oversized">Review</span>
						{{end}}
					</div>
				</div>

				<div>
					<div class="s">Size</div>
					<div>{{.Size}} bytes</div>
				</div>
			</div>

			<hr>

			{{if eq .Kind "managed"}}
			<form
				id="aamm-alert-form"
				method="post"
				action="{{$.BasePath}}/alerts/{{.Target}}"
			>
				<div class="o">Message</div>
				<textarea
					class="aamm-message-editor"
					id="message"
					name="message"
					required
				>{{.Message}}</textarea>
				<div class="m">
					Maximum 4096 bytes.
				</div>
			</form>

			{{else if eq .Kind "legacy"}}
			<div class="o">Existing alert</div>
			<div class="m">
				This alert was not created by AAMM-NG.
				Convert it before editing.
			</div>

			<div class="o">Original content</div>
			<pre class="aamm-source-preview">{{.LegacySource}}</pre>

			<form
				id="aamm-alert-form"
				method="post"
				action="{{$.BasePath}}/alerts/{{.Target}}/convert"
			>
				<div class="o">Replacement message</div>
				<textarea
					class="aamm-message-editor"
					id="message"
					name="message"
					required
				></textarea>
				<div class="m">
					AAMM-NG will back up the existing alert before conversion.
				</div>
			</form>

			{{else if eq .Kind "oversized"}}
			<div class="o">Manual review required</div>
			<div class="m">
				This alert is larger than AAMM-NG can safely edit.
			</div>
			{{end}}
		</div>

		<div class="ctrl-modal-footer">
			<hr>

			<div class="aamm-modal-actions">
				{{if ne .Kind "oversized"}}
				<a
					class="aamm-delete-link"
					href="{{$.BasePath}}/alerts/{{.Target}}/delete"
				>
					Delete alert
				</a>
				{{end}}

				<button type="button" data-aamm-close>
					Cancel
				</button>

				{{if or (eq .Kind "managed") (eq .Kind "legacy")}}
				<button
					id="dialog-done"
					type="submit"
					form="aamm-alert-form"
				>
					{{if eq .Kind "managed"}}Save{{else}}Convert{{end}}
				</button>
				{{end}}
			</div>
		</div>

	</div>
</dialog>
{{end}}

{{with .DeleteModal}}
<dialog
	id="ctrl-modal"
	data-return-url="{{$.BasePath}}/alerts/{{.Target}}"
>
	<div class="dialog">

		<div>
			<div class="t">Delete AAMM-NG Alert</div>
			<div class="s">{{.Target}}</div>
			<hr>
		</div>

		<div>
			<div class="aamm-delete-warning">
				<div class="o">Confirm deletion</div>
				<div class="m">
					This will remove the alert from this node.
					AAMM-NG will create a backup before deletion.
				</div>
			</div>

			<div class="aamm-modal-meta">
				<div>
					<div class="s">Target</div>
					<div class="t aamm-modal-target">{{.Target}}</div>
				</div>

				<div>
					<div class="s">Status</div>
					<div>
						{{if eq .Kind "managed"}}
						<span class="aamm-kind aamm-managed">Managed</span>
						{{else if eq .Kind "legacy"}}
						<span class="aamm-kind aamm-existing">Existing</span>
						{{else if eq .Kind "oversized"}}
						<span class="aamm-kind aamm-oversized">Review</span>
						{{end}}
					</div>
				</div>

				<div>
					<div class="s">Size</div>
					<div>{{.Size}} bytes</div>
				</div>
			</div>

			<hr>

			<form
				id="aamm-delete-form"
				method="post"
				action="{{$.BasePath}}/alerts/{{.Target}}/delete"
			>
				<div class="aamm-delete-confirm">
					<label for="confirm">
						Type <strong>{{.Target}}</strong> to confirm deletion:
					</label>

					<input
						id="confirm"
						name="confirm"
						type="text"
						autocomplete="off"
						data-aamm-confirm-target="{{.Target}}"
						required
					>
				</div>
			</form>
		</div>

		<div class="ctrl-modal-footer">
			<hr>

			<div class="aamm-modal-actions">
				<button type="button" data-aamm-close>
					Cancel
				</button>

				<button
					id="dialog-done"
					class="aamm-danger-button"
					type="submit"
					form="aamm-delete-form"
					data-aamm-delete-submit
					disabled
				>
					Delete
				</button>
			</div>
		</div>

	</div>
</dialog>
{{end}}

<div id="all">

<div id="nav">
	<a
		class="aamm-brand-icon"
		href="{{.BasePath}}/"
		title="AAMM-NG dashboard"
	>
		<img src="/apps/AAMM-NG/icon.svg" alt="">
	</a>

	<a class="nav-node-name" href="{{.BasePath}}/">
		AAMM-NG
	</a>

	<div id="nav-status">
		Next Generation Alert Manager
	</div>

	<div class="aamm-nav-spacer"></div>

	<a class="aamm-back-link" href="/a/status">
		Back to AREDN Status
	</a>
</div>

<div id="panel">

	<div id="select">
		<div>
			<a
				title="Back to AREDN status"
				href="/a/status"
			>
				<div class="icon status"></div>
			</a>

			<hr>

			<a
				class="aamm-rail-link"
				title="AAMM-NG alerts"
				href="{{.BasePath}}/"
			>
				<img
					class="aamm-rail-icon"
					src="/apps/AAMM-NG/icon.svg"
					alt=""
				>
			</a>
		</div>
	</div>

	<div id="main">
		<div id="main-container">
			<div class="aamm-dashboard">

				<div class="aamm-page-header">
					<div>
						<div class="aamm-page-title">
							AAMM-NG Alert Message Manager
						</div>

						<div class="aamm-page-subtitle">
							Next-generation AREDN alert management for this node.
						</div>
					</div>

					<div class="aamm-page-actions">
						<div class="aamm-alert-count">
							{{len .Entries}} alert{{if ne (len .Entries) 1}}s{{end}}
						</div>

						<a
							class="aamm-new-alert-button"
							href="{{.BasePath}}/alerts/new"
						>
							+ New Alert
						</a>
					</div>
				</div>

				<div class="section">
					<div class="section-title">
						Current Alerts
					</div>

					{{if .Entries}}

					<div class="aamm-alert-list">
						{{range .Entries}}
						<a
							class="aamm-alert-row"
							href="{{$.BasePath}}/alerts/{{.Target}}"
						>
							<div class="aamm-alert-target">
								<div class="aamm-target-line">
									<span class="t">{{.Target}}</span>

									{{if eq .Kind "managed"}}
									<span class="aamm-kind aamm-managed">
										Managed
									</span>
									{{else if eq .Kind "legacy"}}
									<span class="aamm-kind aamm-existing">
										Existing
									</span>
									{{else if eq .Kind "oversized"}}
									<span class="aamm-kind aamm-oversized">
										Review
									</span>
									{{end}}
								</div>

								<div class="s">
									{{.Size}} bytes
								</div>
							</div>

							<div class="aamm-alert-message">
								{{if eq .Kind "managed"}}
									{{.Message}}
								{{else if eq .Kind "legacy"}}
									Existing alert — conversion required
								{{else if eq .Kind "oversized"}}
									Oversized alert — manual review required
								{{else}}
									Unknown alert type
								{{end}}
							</div>

							<div class="aamm-row-arrow" aria-hidden="true">
								›
							</div>
						</a>
						{{end}}
					</div>

					{{else}}

					<div class="aamm-empty-state">
						<div class="t">No alert files found</div>
						<div class="s">
							This node does not currently have any AAM alert messages.
						</div>
					</div>

					{{end}}
				</div>

				{{if .Issues}}
				<div class="section">
					<div class="section-title">
						Inspection Issues
					</div>

					<div class="aamm-issues">
						{{range .Issues}}
						<div class="aamm-issue">
							<span class="t">{{.Name}}</span>
							<span class="s">{{.Kind}}</span>
						</div>
						{{end}}
					</div>
				</div>
				{{end}}

			</div>
		</div>
	</div>

</div>
</div>
</body>
</html>
`),
)
