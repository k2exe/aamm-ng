package portal

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/auditidentity"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

func TestViewerCanReadButNeverChange(t *testing.T) {
	e := newEnv(t)
	viewer := e.loginAs("bob")

	home := e.do(viewer.get("/"))
	body := home.Body.String()

	if home.Code != http.StatusOK || !strings.Contains(body, "viewer") || strings.Contains(body, "New alert") {
		t.Fatalf("home page for a viewer:\n%s", body)
	}

	view := e.do(viewer.get("/alerts/all"))
	page := view.Body.String()

	if view.Code != http.StatusOK || !strings.Contains(page, "Net at 7 PM") {
		t.Fatalf("a viewer cannot read an alert: status = %d", view.Code)
	}

	for _, form := range []string{`action="/alerts/all"`, `action="/alerts/all/delete"`, `action="/alerts/all/convert"`, `<textarea`} {
		if strings.Contains(page, form) {
			t.Errorf("the viewer's page contains %s", form)
		}
	}

	if recorder := e.do(viewer.get("/alerts/new")); recorder.Code != http.StatusForbidden {
		t.Errorf("GET /alerts/new as a viewer: status = %d", recorder.Code)
	}

	attempts := map[string]*http.Request{
		"create":  viewer.post("/alerts/new", url.Values{"target": {"node-a"}, "message": {"x"}}),
		"write":   viewer.post("/alerts/all", url.Values{"message": {"x"}}),
		"delete":  viewer.post("/alerts/all/delete", url.Values{"confirm": {"all"}}),
		"convert": viewer.post("/alerts/all/convert", url.Values{"message": {"x"}}),
	}

	for label, request := range attempts {
		if recorder := e.do(request); recorder.Code != http.StatusForbidden {
			t.Errorf("%s as a viewer: status = %d; want 403", label, recorder.Code)
		}
	}

	if changes := e.backend.changes(); len(changes) != 0 {
		t.Fatalf("a viewer changed alerts: %+v", changes)
	}
}

func TestEditorChangesCarryTheirIdentity(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	e.backend.entries["old"] = localcontrol.EntryResult{Target: "old", Kind: "legacy", LegacySource: "old text", Size: 8}

	steps := map[string]*http.Request{
		"create":  editor.post("/alerts/new", url.Values{"target": {"node-a"}, "message": {"Net tonight"}}),
		"write":   editor.post("/alerts/all", url.Values{"message": {"Updated"}}),
		"convert": editor.post("/alerts/old/convert", url.Values{"message": {"Replacement"}}),
		"delete":  editor.post("/alerts/all/delete", url.Values{"confirm": {"all"}}),
	}

	for _, operation := range []string{"create", "write", "convert", "delete"} {
		if recorder := e.do(steps[operation]); recorder.Code != http.StatusSeeOther {
			t.Fatalf("%s: status = %d\n%s", operation, recorder.Code, recorder.Body)
		}

		change, ok := e.backend.last(operation)
		if !ok {
			t.Fatalf("%s: the daemon was not called", operation)
		}

		want := auditidentity.Identity{
			Name:     "alice",
			SourceIP: testIP,
			Method:   auditidentity.MethodPortal,
			Role:     "editor",
		}

		if !change.hasIdentity || change.identity != want {
			t.Errorf("%s: identity = %+v; want %+v", operation, change.identity, want)
		}
	}

	create, _ := e.backend.last("create")
	if create.args[0] != "node-a" || create.args[1] != "Net tonight" {
		t.Errorf("create arguments = %v", create.args)
	}

	if len(e.backend.changes()) != 4 {
		t.Errorf("changes = %d; want 4", len(e.backend.changes()))
	}
}

func TestReadsCarryTheViewersIdentity(t *testing.T) {
	e := newEnv(t)
	viewer := e.loginAs("bob")

	e.do(viewer.get("/"))
	e.do(viewer.get("/alerts/all"))

	for _, operation := range []string{"list", "read"} {
		entry, ok := e.backend.last(operation)
		if !ok || entry.identity.Name != "bob" || entry.identity.Role != "viewer" || entry.identity.Method != auditidentity.MethodPortal {
			t.Errorf("%s: %+v", operation, entry)
		}
	}
}

func TestTheClientCannotSupplyItsOwnRoleOrIdentity(t *testing.T) {
	e := newEnv(t)
	viewer := e.loginAs("bob")

	form := url.Values{
		"target": {"node-a"}, "message": {"x"},
		"role": {"editor"}, "user": {"alice"}, "name": {"alice"}, "auth_role": {"admin"},
	}

	request := viewer.post("/alerts/new?role=editor&user=alice", form,
		withHeader("X-Role", "editor"), withHeader("X-User", "alice"), withHeader("X-AAMM-Remote-Addr", "10.0.0.1"))

	if recorder := e.do(request); recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", recorder.Code)
	}

	editor := e.loginAs("alice", withIP("192.0.2.13"))

	request = editor.post("/alerts/new", url.Values{
		"target": {"node-b"}, "message": {"y"}, "name": {"bob"}, "role": {"viewer"}, "user": {"bob"},
	}, withIP("192.0.2.13"), withHeader("X-User", "bob"))

	if recorder := e.do(request); recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", recorder.Code)
	}

	change, _ := e.backend.last("create")
	if change.identity.Name != "alice" || change.identity.Role != "editor" {
		t.Fatalf("identity = %+v; the request chose it", change.identity)
	}

	if len(e.backend.changes()) != 1 {
		t.Fatalf("changes = %d; want only the editor's", len(e.backend.changes()))
	}
}

func TestEveryAuthenticatedPostNeedsTheSessionsCSRFToken(t *testing.T) {
	e := newEnv(t)

	alice := e.loginAs("alice")
	bob := e.loginAs("bob", withIP("192.0.2.14"))

	targets := map[string]url.Values{
		"/alerts/new":         {"target": {"node-a"}, "message": {"x"}},
		"/alerts/all":         {"message": {"x"}},
		"/alerts/all/delete":  {"confirm": {"all"}},
		"/alerts/all/convert": {"message": {"x"}},
		"/logout":             {},
	}

	for path, base := range targets {
		cases := map[string]url.Values{
			"no csrf":        withCSRF(base, nil),
			"empty csrf":     withCSRF(base, []string{""}),
			"wrong csrf":     withCSRF(base, []string{strings.Repeat("0", len(alice.csrf))}),
			"another csrf":   withCSRF(base, []string{bob.csrf}),
			"duplicate csrf": withCSRF(base, []string{alice.csrf, alice.csrf}),
			"session token":  withCSRF(base, []string{alice.token}),
		}

		for label, form := range cases {
			recorder := e.do(newRequest("POST", path, form, withCookie(alice.token)))

			if recorder.Code != http.StatusForbidden {
				t.Errorf("POST %s with %s: status = %d; want 403", path, label, recorder.Code)
			}
		}

		// A token in the URL does not count.
		recorder := e.do(newRequest("POST", path+"?csrf="+alice.csrf, withCSRF(base, nil), withCookie(alice.token)))
		if recorder.Code != http.StatusForbidden {
			t.Errorf("POST %s with csrf in the URL: status = %d", path, recorder.Code)
		}
	}

	if changes := e.backend.changes(); len(changes) != 0 {
		t.Fatalf("an alert was changed without a valid CSRF token: %+v", changes)
	}

	if recorder := e.do(alice.get("/")); !strings.Contains(recorder.Body.String(), "alice") {
		t.Fatal("a rejected logout ended the session")
	}

	// The right token works.
	if recorder := e.do(alice.post("/alerts/new", url.Values{"target": {"node-a"}, "message": {"x"}})); recorder.Code != http.StatusSeeOther {
		t.Fatalf("a valid post: status = %d", recorder.Code)
	}
}

func withCSRF(base url.Values, values []string) url.Values {
	form := url.Values{}

	for key, value := range base {
		form[key] = append([]string(nil), value...)
	}

	if values != nil {
		form["csrf"] = values
	}

	return form
}

func TestAuthenticatedPostsNeedASameOrigin(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	form := url.Values{"target": {"node-a"}, "message": {"x"}}

	for label, option := range map[string]requestOption{
		"no origin":    withoutHeader("Origin"),
		"evil origin":  withHeader("Origin", "http://evil.test"),
		"null origin":  withHeader("Origin", "null"),
		"https origin": withHeader("Origin", "https://"+testHost),
	} {
		recorder := e.do(editor.post("/alerts/new", form, option))

		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d", label, recorder.Code)
		}
	}

	if len(e.backend.changes()) != 0 {
		t.Fatal("an alert was changed by a cross-origin post")
	}
}

func TestDeleteNeedsTheExactTargetName(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	for _, confirm := range []string{"", "ALL", "al", "all ", "all\n", "node-a", "all&confirm=all"} {
		recorder := e.do(editor.post("/alerts/all/delete", url.Values{"confirm": {confirm}}))

		if recorder.Code != http.StatusBadRequest {
			t.Errorf("confirm %q: status = %d; want 400", confirm, recorder.Code)
		}
	}

	if e.backend.count("delete") != 0 {
		t.Fatal("an alert was deleted without the right confirmation")
	}

	// A confirmation sent twice is refused.
	recorder := e.do(editor.post("/alerts/all/delete", url.Values{"confirm": {"all", "all"}}))
	if recorder.Code != http.StatusBadRequest || e.backend.count("delete") != 0 {
		t.Fatalf("a repeated confirm field: status = %d", recorder.Code)
	}

	if recorder := e.do(editor.post("/alerts/all/delete", url.Values{"confirm": {"all"}})); recorder.Code != http.StatusSeeOther {
		t.Fatalf("a correct confirmation: status = %d", recorder.Code)
	}

	if e.backend.count("delete") != 1 {
		t.Fatalf("delete calls = %d", e.backend.count("delete"))
	}
}

func TestInvalidPathTargetsNeverReachTheDaemon(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	paths := []string{
		"/alerts/%2e%2e", "/alerts/a%2Fb", "/alerts/%3Cscript%3E", "/alerts/-bad",
		"/alerts/bad%20name", "/alerts/%00", "/alerts/" + strings.Repeat("a", 64),
		"/alerts/a.b", "/alerts/a;b", "/alerts/a%5Cb", "/alerts/%E2%80%AEevil",
	}

	for _, path := range paths {
		for _, suffix := range []string{"", "/delete", "/convert"} {
			get := e.do(editor.get(path + suffix))
			post := e.do(editor.post(path+suffix, url.Values{"message": {"x"}, "confirm": {"x"}}))

			for label, recorder := range map[string]*httpRecorder{"GET": {get.Code}, "POST": {post.Code}} {
				if recorder.code != http.StatusNotFound &&
					recorder.code != http.StatusMethodNotAllowed &&
					recorder.code != http.StatusMovedPermanently {
					t.Errorf("%s %s%s: status = %d", label, path, suffix, recorder.code)
				}
			}
		}
	}

	for _, operation := range []string{"read", "write", "convert", "delete"} {
		if count := e.backend.count(operation); count != 0 {
			t.Errorf("%s was called %d times with an invalid target", operation, count)
		}
	}
}

type httpRecorder struct{ code int }

func TestErrorsNeverLeakInternalDetails(t *testing.T) {
	secret := "open /etc/shadow: permission denied password=hunter2 /run/aamm-ng/aamm-ng.sock"

	failures := map[string]error{
		"internal":     &localcontrol.RemoteError{Code: localcontrol.ErrorInternal, Message: secret},
		"unknown code": &localcontrol.RemoteError{Code: "surprise", Message: secret},
		"store closed": &localcontrol.RemoteError{Code: localcontrol.ErrorStoreClosed, Message: secret},
		"unavailable":  fmt.Errorf("%w: connect: dial unix /run/aamm-ng/aamm-ng.sock: %s", localcontrol.ErrControlUnavailable, secret),
		"plain error":  errors.New(secret),
		"timeout":      context.DeadlineExceeded,
	}

	for label, failure := range failures {
		e := newEnv(t)
		editor := e.loginAs("alice")
		e.backend.failure = failure

		responses := map[string]string{
			"list":   e.do(editor.get("/")).Body.String(),
			"read":   e.do(editor.get("/alerts/all")).Body.String(),
			"create": e.do(editor.post("/alerts/new", url.Values{"target": {"node-a"}, "message": {"x"}})).Body.String(),
			"write":  e.do(editor.post("/alerts/all", url.Values{"message": {"x"}})).Body.String(),
		}

		for operation, body := range responses {
			for _, leak := range []string{"shadow", "hunter2", "/run/aamm-ng", "dial unix", "permission denied", "surprise"} {
				if strings.Contains(body, leak) {
					t.Errorf("%s/%s: the response contains %q", label, operation, leak)
				}
			}
		}

		if recorder := e.do(editor.get("/")); recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d; want 503", label, recorder.Code)
		}
	}
}

func TestBackendErrorCodesMapToStatuses(t *testing.T) {
	cases := map[string]int{
		localcontrol.ErrorNotFound:          http.StatusNotFound,
		localcontrol.ErrorAlreadyExists:     http.StatusConflict,
		localcontrol.ErrorInvalidTarget:     http.StatusBadRequest,
		localcontrol.ErrorInvalidMessage:    http.StatusBadRequest,
		localcontrol.ErrorInvalidRequest:    http.StatusBadRequest,
		localcontrol.ErrorLegacyConflict:    http.StatusConflict,
		localcontrol.ErrorOversizedConflict: http.StatusConflict,
		localcontrol.ErrorManagedConflict:   http.StatusConflict,
		localcontrol.ErrorSourceChanged:     http.StatusConflict,
		localcontrol.ErrorUnsafeFile:        http.StatusConflict,
		localcontrol.ErrorForbidden:         http.StatusForbidden,
		localcontrol.ErrorInternal:          http.StatusServiceUnavailable,
		localcontrol.ErrorStoreClosed:       http.StatusServiceUnavailable,
		localcontrol.ErrorPortalUnavailable: http.StatusServiceUnavailable,
	}

	for code, want := range cases {
		status, text := describe(&localcontrol.RemoteError{Code: code, Message: "detail that must not be shown"})

		if status != want {
			t.Errorf("code %q: status = %d; want %d", code, status, want)
		}

		if text == "" || strings.Contains(text, "detail that must not be shown") {
			t.Errorf("code %q: text = %q", code, text)
		}
	}
}

func TestFormsKeepTheUsersInputWhenAnErrorOccurs(t *testing.T) {
	e := newEnv(t)
	editor := e.loginAs("alice")

	e.backend.failure = &localcontrol.RemoteError{Code: localcontrol.ErrorAlreadyExists, Message: "exists"}

	recorder := e.do(editor.post("/alerts/new", url.Values{"target": {"all"}, "message": {"My long message"}}))

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d", recorder.Code)
	}

	body := recorder.Body.String()

	if !strings.Contains(body, "already exists") || !strings.Contains(body, "My long message") || !strings.Contains(body, `value="all"`) {
		t.Fatalf("the form lost its input:\n%s", body)
	}
}

type fakeNodes struct {
	names []string
	err   error
}

func (nodes fakeNodes) LocalNodes(context.Context) ([]string, error) {
	return nodes.names, nodes.err
}

func TestNewAlertPageListsNodesAndSurvivesLookupFailure(t *testing.T) {
	e := newEnvWithNodes(t, fakeNodes{names: []string{"k2exe-ar300", `<b>evil</b>`}})
	editor := e.loginAs("alice")

	body := e.do(editor.get("/alerts/new")).Body.String()

	if !strings.Contains(body, `<option value="k2exe-ar300">`) || strings.Contains(body, "<b>evil</b>") {
		t.Fatalf("node list:\n%s", body)
	}

	failing := newEnvWithNodes(t, fakeNodes{err: errors.New("no hosts file")})
	editor = failing.loginAs("alice")

	recorder := failing.do(editor.get("/alerts/new"))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `<option value="all">`) {
		t.Fatalf("status = %d", recorder.Code)
	}
}
