package portal

import (
	"html/template"
	"unicode/utf8"

	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

type pageData struct {
	Title       string
	Session     *Session
	Login       bool
	New         bool
	Entry       *localcontrol.EntryResult
	Entries     []localcontrol.EntryResult
	Issues      int
	Notice      string
	Error       string
	FormTarget  string
	FormMessage string
	Nodes       []string
}

// IsEditor reports whether the signed-in user may change alerts.
func (data pageData) IsEditor() bool {
	return data.Session != nil &&
		data.Session.Role == localcontrol.RoleEditor
}

func preview(text string, limit int) string {
	if utf8.RuneCountInString(text) <= limit {
		return text
	}

	runes := []rune(text)

	return string(runes[:limit]) + "…"
}

var pageTemplate = template.Must(
	template.New("page").
		Funcs(template.FuncMap{"preview": preview}).
		Parse(pageText),
)

// render writes a page. Every value is escaped by html/template, so an
// alert message can never become markup.
func render(
	writer http.ResponseWriter,
	_ *http.Request,
	status int,
	data pageData,
) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)

	_ = pageTemplate.Execute(writer, data)
}

const pageText = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - AAMM-NG Portal</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<header>
  <a class="brand" href="/">AAMM-NG <span>Portal</span></a>
  {{if .Session}}
  <div class="who">
    <span class="user">{{.Session.User}}</span>
    <span class="role role-{{.Session.Role}}">{{.Session.Role}}</span>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf" value="{{.Session.CSRF}}">
      <button type="submit" class="link">Sign out</button>
    </form>
  </div>
  {{end}}
</header>
<main>
{{if .Notice}}<p class="notice" role="status">{{.Notice}}</p>{{end}}
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}

{{if .Login}}
  <h1>Sign in</h1>
  <form method="post" action="/login" class="card">
    <label for="name">User name</label>
    <input id="name" name="name" type="text" autocomplete="username"
      autocapitalize="none" spellcheck="false" maxlength="64" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password"
      autocomplete="current-password" maxlength="256" required>
    <button type="submit">Sign in</button>
  </form>
  <p class="hint">This page is not encrypted. Do not reuse a password from another service.</p>

{{else if .New}}
  <h1>New alert</h1>
  <form method="post" action="/alerts/new" class="card">
    <input type="hidden" name="csrf" value="{{.Session.CSRF}}">
    <label for="target">Target</label>
    <input id="target" name="target" type="text" list="nodes" value="{{.FormTarget}}"
      autocapitalize="none" spellcheck="false" maxlength="255" required>
    <datalist id="nodes">
      <option value="all">
      {{range .Nodes}}<option value="{{.}}">{{end}}
    </datalist>
    <p class="hint">Use <b>all</b> for all nodes, a group name, or a node name.</p>
    <label for="message">Message</label>
    <textarea id="message" name="message" rows="8" required>{{.FormMessage}}</textarea>
    <p class="hint">At most 4096 bytes. An existing alert is never overwritten.</p>
    <div class="actions">
      <button type="submit">Create</button>
      <a class="button secondary" href="/">Cancel</a>
    </div>
  </form>

{{else if .Entry}}
  <h1>Alert: {{.Entry.Target}}</h1>
  <p class="meta">{{.Entry.Kind}} &middot; {{.Entry.Size}} bytes</p>

  {{if eq .Entry.Kind "managed"}}
    {{if .IsEditor}}
    <form method="post" action="/alerts/{{.Entry.Target}}" class="card">
      <input type="hidden" name="csrf" value="{{.Session.CSRF}}">
      <label for="message">Message</label>
      <textarea id="message" name="message" rows="8" required>{{if .FormMessage}}{{.FormMessage}}{{else}}{{.Entry.Message}}{{end}}</textarea>
      <div class="actions">
        <button type="submit">Save</button>
        <a class="button secondary" href="/">Back</a>
      </div>
    </form>
    <form method="post" action="/alerts/{{.Entry.Target}}/delete" class="card danger">
      <input type="hidden" name="csrf" value="{{.Session.CSRF}}">
      <label for="confirm">Delete this alert</label>
      <p class="hint">Type <b>{{.Entry.Target}}</b> to confirm. A backup is kept.</p>
      <input id="confirm" name="confirm" type="text" autocomplete="off"
        autocapitalize="none" spellcheck="false" required>
      <button type="submit" class="danger">Delete</button>
    </form>
    {{else}}
    <pre class="message">{{.Entry.Message}}</pre>
    <p><a class="button secondary" href="/">Back</a></p>
    {{end}}

  {{else if eq .Entry.Kind "legacy"}}
    <p class="hint">This file was not created by AAMM-NG. Its current content is shown below.</p>
    <pre class="message">{{if .Entry.LegacySource}}{{.Entry.LegacySource}}{{else}}{{.Entry.Message}}{{end}}</pre>
    {{if .IsEditor}}
    <form method="post" action="/alerts/{{.Entry.Target}}/convert" class="card">
      <input type="hidden" name="csrf" value="{{.Session.CSRF}}">
      <label for="message">Replacement message</label>
      <textarea id="message" name="message" rows="8" required>{{.FormMessage}}</textarea>
      <p class="hint">Converting replaces the file. A backup is kept first.</p>
      <div class="actions">
        <button type="submit">Convert</button>
        <a class="button secondary" href="/">Back</a>
      </div>
    </form>
    {{else}}
    <p><a class="button secondary" href="/">Back</a></p>
    {{end}}

  {{else}}
    <p class="hint">This file is too large to be managed here.</p>
    <p><a class="button secondary" href="/">Back</a></p>
  {{end}}

{{else if .Session}}
  <div class="title-row">
    <h1>Alerts</h1>
    {{if .IsEditor}}<a class="button" href="/alerts/new">New alert</a>{{end}}
  </div>
  {{if .Entries}}
  <table>
    <thead><tr><th>Target</th><th>Kind</th><th>Message</th><th>Bytes</th></tr></thead>
    <tbody>
    {{range .Entries}}
      <tr>
        <td><a href="/alerts/{{.Target}}">{{.Target}}</a></td>
        <td>{{.Kind}}</td>
        <td>{{preview .Message 90}}</td>
        <td>{{.Size}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="hint">No alerts yet.</p>
  {{end}}
  {{if .Issues}}<p class="hint">{{.Issues}} file{{if ne .Issues 1}}s{{end}} in the alert directory cannot be shown here.</p>{{end}}
{{end}}
</main>
</body>
</html>
`
