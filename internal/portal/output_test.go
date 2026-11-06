package portal

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

const (
	scriptPayload    = `<script>alert(1)</script>`
	imagePayload     = `"><img src=x onerror=alert(1)>`
	textareaPayload  = `</textarea><script>alert(2)</script>`
	attributePayload = `" autofocus onfocus="alert(3)" x="`
)

func assertEscaped(t *testing.T, label, body string) {
	t.Helper()

	for _, raw := range []string{"<script>alert", "<img src=x", `" autofocus onfocus="alert`, "</textarea><script"} {
		if strings.Contains(body, raw) {
			t.Errorf("%s: the page contains unescaped %q", label, raw)
		}
	}
}

func TestUserContentIsEscapedEverywhere(t *testing.T) {
	e := newEnv(t)

	e.backend.entries["xss"] = localcontrol.EntryResult{
		Target: "xss", Kind: "managed", Message: scriptPayload + imagePayload + textareaPayload, Size: 99,
	}
	e.backend.entries["legacy-xss"] = localcontrol.EntryResult{
		Target: "legacy-xss", Kind: "legacy", LegacySource: scriptPayload + imagePayload, Message: textareaPayload,
	}

	editor := e.loginAs("alice")
	viewer := e.loginAs("bob", withIP("192.0.2.15"))

	pages := map[string]string{
		"list (editor)":        e.do(editor.get("/")).Body.String(),
		"view (editor)":        e.do(editor.get("/alerts/xss")).Body.String(),
		"legacy view (editor)": e.do(editor.get("/alerts/legacy-xss")).Body.String(),
		"view (viewer)":        e.do(newRequest("GET", "/alerts/xss", nil, withCookie(viewer.token), withIP("192.0.2.15"))).Body.String(),
		"new alert":            e.do(editor.get("/alerts/new")).Body.String(),
	}

	e.backend.failure = &localcontrol.RemoteError{Code: localcontrol.ErrorInvalidMessage, Message: "bad"}

	pages["create error"] = e.do(editor.post("/alerts/new", url.Values{
		"target": {attributePayload}, "message": {textareaPayload + scriptPayload},
	})).Body.String()

	e.backend.failure = nil

	for label, body := range pages {
		assertEscaped(t, label, body)
	}

	if !strings.Contains(pages["view (editor)"], "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the alert text is not shown as text")
	}

	if !strings.Contains(pages["create error"], "&#34; autofocus onfocus=&#34;alert(3)&#34; x=&#34;") {
		t.Errorf("the target value is not escaped in its attribute:\n%s", pages["create error"])
	}
}

func TestUserNamesAreEscaped(t *testing.T) {
	e := newEnv(t)
	e.backend.users["<i>x</i>"] = localcontrol.PortalLoginResult{Name: `<i>x</i>"><script>alert(1)</script>`, Role: "viewer"}

	recorder := e.do(newRequest("POST", "/login", url.Values{"name": {"<i>x</i>"}, "password": {testPassword}}))
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", recorder.Code)
	}

	page := e.do(newRequest("GET", "/", nil, withCookie(tokenFrom(recorder)))).Body.String()

	assertEscaped(t, "header", page)

	if strings.Contains(page, "<i>x</i>") {
		t.Error("the user name was inserted as markup")
	}
}

func TestSecurityHeadersAreOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	wrong := url.Values{"name": {"alice"}, "password": {"wrong"}}

	requests := map[string]*http.Request{
		"login page":   newRequest("GET", "/", nil, withIP("192.0.2.60")),
		"home":         editor.get("/"),
		"alert":        editor.get("/alerts/all"),
		"not found":    newRequest("GET", "/nothing", nil),
		"not allowed":  newRequest("PUT", "/", nil),
		"redirect":     newRequest("GET", "/alerts/all", nil, withIP("192.0.2.61")),
		"forbidden":    newRequest("POST", "/login", url.Values{"name": {"a"}}, withoutHeader("Origin")),
		"unauthorized": newRequest("POST", "/login", wrong, withIP("192.0.2.62")),
		"stylesheet":   newRequest("GET", "/portal.css", nil),
	}

	for label, request := range requests {
		recorder := e.do(request)
		header := recorder.Header()

		csp := header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "style-src 'self'", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q is missing %q", label, csp, want)
			}
		}

		if strings.Contains(csp, "unsafe") || strings.Contains(csp, "script-src") || strings.Contains(csp, "*") {
			t.Errorf("%s: CSP %q is too permissive", label, csp)
		}

		if header.Get("X-Frame-Options") != "DENY" ||
			header.Get("X-Content-Type-Options") != "nosniff" ||
			header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing a security header: %v", label, header)
		}

		if label != "stylesheet" && !strings.Contains(header.Get("Cache-Control"), "no-store") {
			t.Errorf("%s: Cache-Control = %q", label, header.Get("Cache-Control"))
		}
	}
}

func TestPagesUseNoScriptsAndNoExternalResources(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	e.backend.entries["legacy1"] = localcontrol.EntryResult{Target: "legacy1", Kind: "legacy", LegacySource: "old"}

	pages := []string{
		e.do(newRequest("GET", "/", nil, withIP("192.0.2.70"))).Body.String(),
		e.do(editor.get("/")).Body.String(),
		e.do(editor.get("/alerts/new")).Body.String(),
		e.do(editor.get("/alerts/all")).Body.String(),
		e.do(editor.get("/alerts/legacy1")).Body.String(),
	}

	reference := regexp.MustCompile(`(?:href|src|action)="([^"]*)"`)

	for _, page := range pages {
		for _, banned := range []string{"<script", "javascript:", "onclick=", "onload=", "<iframe", "<object", "<embed", "<base"} {
			if strings.Contains(strings.ToLower(page), banned) {
				t.Errorf("a page contains %q", banned)
			}
		}

		for _, match := range reference.FindAllStringSubmatch(page, -1) {
			if !strings.HasPrefix(match[1], "/") && !strings.HasPrefix(match[1], "#") {
				t.Errorf("a page references %q", match[1])
			}

			if strings.HasPrefix(match[1], "//") {
				t.Errorf("a page has a protocol-relative reference %q", match[1])
			}
		}
	}
}

func TestOnlyLoginAndLogoutTouchCookies(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	for _, request := range []*http.Request{
		editor.get("/"), editor.get("/alerts/all"), editor.get("/alerts/new"),
		editor.post("/alerts/new", url.Values{"target": {"node-a"}, "message": {"x"}}),
		newRequest("GET", "/", nil), newRequest("GET", "/portal.css", nil),
	} {
		if cookies := e.do(request).Header().Values("Set-Cookie"); len(cookies) != 0 {
			t.Errorf("%s %s set a cookie: %v", request.Method, request.URL.Path, cookies)
		}
	}
}

func TestStylesheet(t *testing.T) {
	e := newEnv(t)

	recorder := e.do(newRequest("GET", "/portal.css", nil))
	if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("status = %d, type = %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}

	css := recorder.Body.String()

	for _, banned := range []string{"@import", "url(", "expression(", "javascript:"} {
		if strings.Contains(css, banned) {
			t.Errorf("the stylesheet contains %q", banned)
		}
	}

	if head := e.do(newRequest("HEAD", "/portal.css", nil)); head.Code != http.StatusOK {
		t.Errorf("HEAD status = %d", head.Code)
	}
}

func TestLoginFormWarnsThatTheConnectionIsNotEncrypted(t *testing.T) {
	e := newEnv(t)

	body := e.do(newRequest("GET", "/", nil)).Body.String()

	if !strings.Contains(body, "not encrypted") {
		t.Fatal("the login page does not warn about clear-text passwords")
	}

	for _, want := range []string{`autocomplete="username"`, `autocomplete="current-password"`, `type="password"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the login form is missing %s", want)
		}
	}
}
