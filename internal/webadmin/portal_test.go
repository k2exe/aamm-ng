package webadmin

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/k2exe/aamm-ng/internal/appconfig"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
	"github.com/k2exe/aamm-ng/internal/minihttp/httptest"
	"github.com/k2exe/aamm-ng/internal/portal"
)

const (
	adminHost     = "node.local.mesh:11313"
	adminPassword = "correct horse battery"
)

type adminCall struct {
	op   string
	args []string
}

type fakePortalAdmin struct {
	mu       sync.Mutex
	calls    []adminCall
	settings appconfig.Config
	users    []localcontrol.PortalUserResult

	readErr    error
	replaceErr error
	listErr    error
	changeErr  error
}

func (admin *fakePortalAdmin) record(op string, args ...string) {
	admin.mu.Lock()
	defer admin.mu.Unlock()

	admin.calls = append(admin.calls, adminCall{op, args})
}

func (admin *fakePortalAdmin) count(op string) int {
	admin.mu.Lock()
	defer admin.mu.Unlock()

	total := 0

	for _, entry := range admin.calls {
		if entry.op == op {
			total++
		}
	}

	return total
}

func (admin *fakePortalAdmin) total() int {
	admin.mu.Lock()
	defer admin.mu.Unlock()

	return len(admin.calls)
}

func (admin *fakePortalAdmin) last(op string) (adminCall, bool) {
	admin.mu.Lock()
	defer admin.mu.Unlock()

	for index := len(admin.calls) - 1; index >= 0; index-- {
		if admin.calls[index].op == op {
			return admin.calls[index], true
		}
	}

	return adminCall{}, false
}

func (admin *fakePortalAdmin) SettingsRead(context.Context) (appconfig.Config, error) {
	admin.record("settings_read")

	return admin.settings, admin.readErr
}

func (admin *fakePortalAdmin) SettingsReplace(_ context.Context, config appconfig.Config) (appconfig.Config, error) {
	admin.record("settings_replace", boolText(config.Portal.Enabled), config.Portal.Reach)

	if admin.replaceErr != nil {
		return appconfig.Config{}, admin.replaceErr
	}

	admin.settings = config

	return config, nil
}

func (admin *fakePortalAdmin) PortalUsersList(context.Context) (localcontrol.PortalUsersResult, error) {
	admin.record("users_list")

	return localcontrol.PortalUsersResult{Users: admin.users}, admin.listErr
}

func (admin *fakePortalAdmin) PortalUserCreate(_ context.Context, name, role, password string) error {
	admin.record("create", name, role, password)

	return admin.changeErr
}

func (admin *fakePortalAdmin) PortalUserSetPassword(_ context.Context, name, password string) error {
	admin.record("set_password", name, password)

	return admin.changeErr
}

func (admin *fakePortalAdmin) PortalUserSetRole(_ context.Context, name, role string) error {
	admin.record("set_role", name, role)

	return admin.changeErr
}

func (admin *fakePortalAdmin) PortalUserSetDisabled(_ context.Context, name string, disabled bool) error {
	admin.record("set_disabled", name, boolText(disabled))

	return admin.changeErr
}

func (admin *fakePortalAdmin) PortalUserDelete(_ context.Context, name string) error {
	admin.record("delete", name)

	return admin.changeErr
}

func boolText(value bool) string {
	if value {
		return "true"
	}

	return "false"
}

type fakePortalRuntime struct {
	mu        sync.Mutex
	applied   []string
	revoked   []string
	listening bool
	failStart bool
	status    portal.Status
}

func (runtime *fakePortalRuntime) Apply(enabled bool, reach string) portal.Status {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	runtime.applied = append(runtime.applied, boolText(enabled)+" "+reach)
	runtime.listening = enabled && !runtime.failStart

	runtime.status = portal.Status{Enabled: enabled, Reach: reach, Listening: runtime.listening}
	if runtime.listening {
		runtime.status.Address = "0.0.0.0:11314"
	}

	return runtime.status
}

func (runtime *fakePortalRuntime) Status() portal.Status {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	return runtime.status
}

func (runtime *fakePortalRuntime) RevokeUser(name string) int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	runtime.revoked = append(runtime.revoked, name)

	return 1
}

func (runtime *fakePortalRuntime) revocations() []string {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	return append([]string(nil), runtime.revoked...)
}

type portalFixture struct {
	t       *testing.T
	handler http.Handler
	admin   *fakePortalAdmin
	runtime *fakePortalRuntime
	lister  *fakeLister
}

func newPortalFixture(t *testing.T) *portalFixture {
	t.Helper()

	admin := &fakePortalAdmin{
		settings: appconfig.Defaults(),
		users: []localcontrol.PortalUserResult{
			{Name: "alice", Role: "editor", Created: "2026-11-06T00:00:00Z"},
			{Name: "bob", Role: "viewer", Disabled: true, Created: "2026-11-06T00:00:00Z"},
		},
	}

	runtime := &fakePortalRuntime{}

	lister := &fakeLister{settingsResult: appconfig.Defaults()}

	handler := NewHandlerWithPortal(
		&fakeVerifier{authenticated: true},
		lister,
		admin,
		runtime,
	)

	return &portalFixture{t: t, handler: handler, admin: admin, runtime: runtime, lister: lister}
}

func (fixture *portalFixture) get(path string) *httptest.ResponseRecorder {
	fixture.t.Helper()

	request := newTestRequest(http.MethodGet, "http://"+adminHost+path, nil)
	request.Header.Set("Cookie", "authV1=test-value")

	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)

	return recorder
}

func (fixture *portalFixture) post(
	path string,
	form url.Values,
	options ...func(*http.Request),
) *httptest.ResponseRecorder {
	fixture.t.Helper()

	request := newTestRequest(http.MethodPost, "http://"+adminHost+path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://"+adminHost)
	request.Header.Set("Cookie", "authV1=test-value")

	for _, option := range options {
		option(request)
	}

	recorder := httptest.NewRecorder()
	fixture.handler.ServeHTTP(recorder, request)

	return recorder
}

func redirectTo(recorder *httptest.ResponseRecorder) string {
	return recorder.Header().Get("Location")
}

func TestSettingsPageShowsThePortalSection(t *testing.T) {
	fixture := newPortalFixture(t)

	response := fixture.get("/settings")
	body := response.Body.String()

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}

	for _, want := range []string{
		"Multi-user portal",
		"does not use encryption",
		`action="/settings/portal"`,
		"Listens on port 11314",
		"This node's LAN and the mesh",
		"AAMM-NG Portal",
		"<td>node</td>",
		"<td>11314</td>",
		`href="http://node.local.mesh:11314/"`,
		"alice", "bob", "disabled",
		`action="/settings/portal/users/alice/password"`,
		`action="/settings/portal/users/bob/delete"`,
		`value="0"`,
		"Add a user",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the settings page is missing %q", want)
		}
	}

	if !strings.Contains(body, "Enable the user") || !strings.Contains(body, "Disable the user") {
		t.Error("the enable and disable buttons are missing")
	}
}

func TestSettingsPageWithoutThePortalHasNoPortalSection(t *testing.T) {
	handler := NewHandler(&fakeVerifier{authenticated: true}, &fakeLister{settingsResult: appconfig.Defaults()})

	request := authenticatedRequest(t, http.MethodGet, "/settings")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if strings.Contains(recorder.Body.String(), "Multi-user portal") {
		t.Fatal("the portal section appeared without a portal")
	}

	post := authenticatedMutationRequest(t, "/settings/portal", "x", "http://node.local.mesh:11313")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, post)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("POST /settings/portal without a portal: status = %d", recorder.Code)
	}
}

func TestSettingsPageShowsRuntimeStatus(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.runtime.status = portal.Status{Enabled: true, Reach: "lan", Listening: true, Address: "10.1.2.3:11314"}
	fixture.lister.settingsResult.Portal = appconfig.Portal{Enabled: true, Reach: appconfig.ReachLAN}

	body := fixture.get("/settings").Body.String()

	if !strings.Contains(body, "Listening on 10.1.2.3:11314") ||
		!strings.Contains(body, `<option value="lan" selected>`) ||
		!strings.Contains(body, `<option value="1" selected>`) {
		t.Fatalf("settings page:\n%s", body)
	}

	fixture.runtime.status = portal.Status{Enabled: true, Reach: "lan", Error: "The LAN network of this node is not known."}

	body = fixture.get("/settings").Body.String()
	if !strings.Contains(body, "Not listening") || !strings.Contains(body, "The LAN network of this node is not known.") {
		t.Fatal("a start failure is not shown")
	}
}

func TestSettingsPageSurvivesAUserListFailure(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.admin.listErr = errors.New("daemon down at /run/aamm-ng/aamm-ng.sock")

	response := fixture.get("/settings")
	body := response.Body.String()

	if response.Code != http.StatusOK ||
		!strings.Contains(body, "The user list is not available.") ||
		strings.Contains(body, "aamm-ng.sock") ||
		strings.Contains(body, "There are no portal users yet") {
		t.Fatalf("status = %d\n%s", response.Code, body)
	}
}

func TestPortalFormsRequireTheAdministrator(t *testing.T) {
	admin := &fakePortalAdmin{settings: appconfig.Defaults()}
	handler := NewHandlerWithPortal(&fakeVerifier{authenticated: false}, &fakeLister{settingsResult: appconfig.Defaults()}, admin, &fakePortalRuntime{})

	for _, path := range []string{
		"/settings/portal", "/settings/portal/users",
		"/settings/portal/users/alice/role", "/settings/portal/users/alice/password",
		"/settings/portal/users/alice/disabled", "/settings/portal/users/alice/delete",
	} {
		request := newTestRequest(http.MethodPost, "http://"+adminHost+path, strings.NewReader("enabled=1&reach=mesh"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "http://"+adminHost)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("POST %s without a login: status = %d; want 401", path, recorder.Code)
		}
	}

	if admin.total() != 0 {
		t.Fatalf("the daemon was called without a login: %+v", admin.calls)
	}
}

func TestPortalFormsNeedASameOriginPost(t *testing.T) {
	fixture := newPortalFixture(t)

	form := url.Values{"enabled": {"1"}, "reach": {"mesh"}}

	cases := map[string]func(*http.Request){
		"no origin":    func(r *http.Request) { r.Header.Del("Origin") },
		"other origin": func(r *http.Request) { r.Header.Set("Origin", "http://evil.test") },
		"https origin": func(r *http.Request) { r.Header.Set("Origin", "https://"+adminHost) },
		"null origin":  func(r *http.Request) { r.Header.Set("Origin", "null") },
	}

	for label, option := range cases {
		for _, path := range []string{"/settings/portal", "/settings/portal/users/alice/delete"} {
			if recorder := fixture.post(path, form, option); recorder.Code != http.StatusForbidden {
				t.Errorf("%s on %s: status = %d; want 403", label, path, recorder.Code)
			}
		}
	}

	if fixture.admin.total() != 0 || len(fixture.runtime.applied) != 0 {
		t.Fatal("a cross-origin post changed something")
	}
}

func TestPortalFormsRejectOtherMethods(t *testing.T) {
	fixture := newPortalFixture(t)

	for _, path := range []string{
		"/settings/portal", "/settings/portal/users", "/settings/portal/users/alice/role",
		"/settings/portal/users/alice/password", "/settings/portal/users/alice/disabled",
		"/settings/portal/users/alice/delete",
	} {
		recorder := fixture.get(path)

		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "POST" {
			t.Errorf("GET %s: status = %d", path, recorder.Code)
		}
	}
}

func TestSavingPortalSettings(t *testing.T) {
	fixture := newPortalFixture(t)

	recorder := fixture.post("/settings/portal", url.Values{"enabled": {"1"}, "reach": {"lan"}})

	if recorder.Code != http.StatusSeeOther || redirectTo(recorder) != "/settings?notice=portal_saved#portal" {
		t.Fatalf("status = %d, location = %q", recorder.Code, redirectTo(recorder))
	}

	call, ok := fixture.admin.last("settings_replace")
	if !ok || call.args[0] != "true" || call.args[1] != "lan" {
		t.Fatalf("SettingsReplace call = %+v", call)
	}

	if len(fixture.runtime.applied) != 1 || fixture.runtime.applied[0] != "true lan" {
		t.Fatalf("Apply calls = %v", fixture.runtime.applied)
	}

	recorder = fixture.post("/settings/portal", url.Values{"enabled": {"0"}, "reach": {"mesh"}})
	if recorder.Code != http.StatusSeeOther || fixture.runtime.applied[1] != "false mesh" {
		t.Fatalf("disabling: status = %d, applied = %v", recorder.Code, fixture.runtime.applied)
	}
}

func TestSavingPortalSettingsRejectsBadForms(t *testing.T) {
	fixture := newPortalFixture(t)

	cases := map[string]url.Values{
		"enabled 2":       {"enabled": {"2"}, "reach": {"mesh"}},
		"enabled word":    {"enabled": {"true"}, "reach": {"mesh"}},
		"enabled empty":   {"enabled": {""}, "reach": {"mesh"}},
		"reach internet":  {"enabled": {"1"}, "reach": {"internet"}},
		"reach upper":     {"enabled": {"1"}, "reach": {"LAN"}},
		"reach empty":     {"enabled": {"1"}, "reach": {""}},
		"missing reach":   {"enabled": {"1"}},
		"missing enabled": {"reach": {"mesh"}},
		"extra field":     {"enabled": {"1"}, "reach": {"mesh"}, "port": {"80"}},
		"duplicate":       {"enabled": {"1", "0"}, "reach": {"mesh"}},
		"nothing":         {},
	}

	for label, form := range cases {
		recorder := fixture.post("/settings/portal", form)

		if recorder.Code != http.StatusSeeOther || redirectTo(recorder) != "/settings?problem=invalid_form#portal" {
			t.Errorf("%s: status = %d, location = %q", label, recorder.Code, redirectTo(recorder))
		}
	}

	if fixture.admin.total() != 0 || len(fixture.runtime.applied) != 0 {
		t.Fatalf("a bad form changed something: %+v %v", fixture.admin.calls, fixture.runtime.applied)
	}
}

func TestSavingPortalSettingsFailureModes(t *testing.T) {
	// The daemon cannot be read.
	fixture := newPortalFixture(t)
	fixture.admin.readErr = errors.New("down")

	recorder := fixture.post("/settings/portal", url.Values{"enabled": {"1"}, "reach": {"mesh"}})
	if redirectTo(recorder) != "/settings?problem=unavailable#portal" || len(fixture.runtime.applied) != 0 {
		t.Fatalf("read failure: %q, applied %v", redirectTo(recorder), fixture.runtime.applied)
	}

	// The save fails: the portal must not start.
	fixture = newPortalFixture(t)
	fixture.admin.replaceErr = &localcontrol.RemoteError{Code: localcontrol.ErrorInternal, Message: "disk full /etc/aamm-ng"}

	recorder = fixture.post("/settings/portal", url.Values{"enabled": {"1"}, "reach": {"mesh"}})
	if redirectTo(recorder) != "/settings?problem=unavailable#portal" || len(fixture.runtime.applied) != 0 {
		t.Fatalf("save failure: %q, applied %v", redirectTo(recorder), fixture.runtime.applied)
	}

	if strings.Contains(redirectTo(recorder), "disk") {
		t.Fatal("an internal error reached the redirect")
	}

	// The save is applied but may not be durable: still start the portal.
	fixture = newPortalFixture(t)
	fixture.admin.replaceErr = &localcontrol.RemoteError{Code: localcontrol.ErrorSettingsDurabilityUncertain}

	recorder = fixture.post("/settings/portal", url.Values{"enabled": {"1"}, "reach": {"mesh"}})
	if redirectTo(recorder) != "/settings?notice=durability#portal" || len(fixture.runtime.applied) != 1 {
		t.Fatalf("durability: %q, applied %v", redirectTo(recorder), fixture.runtime.applied)
	}

	// The portal cannot start.
	fixture = newPortalFixture(t)
	fixture.runtime.failStart = true

	recorder = fixture.post("/settings/portal", url.Values{"enabled": {"1"}, "reach": {"lan"}})
	if redirectTo(recorder) != "/settings?problem=listen_failed#portal" {
		t.Fatalf("start failure: %q", redirectTo(recorder))
	}

	// A forbidden daemon answer is shown as forbidden.
	fixture = newPortalFixture(t)
	fixture.admin.replaceErr = &localcontrol.RemoteError{Code: localcontrol.ErrorForbidden}

	recorder = fixture.post("/settings/portal", url.Values{"enabled": {"1"}, "reach": {"mesh"}})
	if redirectTo(recorder) != "/settings?problem=forbidden#portal" {
		t.Fatalf("forbidden: %q", redirectTo(recorder))
	}
}

func TestSavingPortalSettingsKeepsOtherSettings(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.admin.settings = appconfig.Config{Version: appconfig.CurrentVersion}

	fixture.post("/settings/portal", url.Values{"enabled": {"1"}, "reach": {"mesh"}})

	if fixture.admin.settings.Version != appconfig.CurrentVersion ||
		!fixture.admin.settings.Portal.Enabled || fixture.admin.settings.Portal.Reach != "mesh" {
		t.Fatalf("settings = %+v", fixture.admin.settings)
	}
}

func TestCreatingAUser(t *testing.T) {
	fixture := newPortalFixture(t)

	form := url.Values{"name": {"carol"}, "role": {"editor"}, "password": {adminPassword}, "confirm": {adminPassword}}

	recorder := fixture.post("/settings/portal/users", form)

	if recorder.Code != http.StatusSeeOther || redirectTo(recorder) != "/settings?notice=user_created#portal" {
		t.Fatalf("status = %d, location = %q", recorder.Code, redirectTo(recorder))
	}

	call, ok := fixture.admin.last("create")
	if !ok || call.args[0] != "carol" || call.args[1] != "editor" || call.args[2] != adminPassword {
		t.Fatalf("create call = %+v", call)
	}
}

func TestCreatingAUserRejectsBadInput(t *testing.T) {
	fixture := newPortalFixture(t)

	good := func() url.Values {
		return url.Values{"name": {"carol"}, "role": {"editor"}, "password": {adminPassword}, "confirm": {adminPassword}}
	}

	mismatch := good()
	mismatch.Set("confirm", adminPassword+"x")

	extra := good()
	extra.Set("disabled", "1")

	missing := good()
	missing.Del("confirm")

	duplicate := good()
	duplicate["name"] = []string{"carol", "dave"}

	cases := map[string]struct {
		form url.Values
		want string
	}{
		"passwords differ": {mismatch, "passwords_differ"},
		"extra field":      {extra, "invalid_form"},
		"missing confirm":  {missing, "invalid_form"},
		"duplicate name":   {duplicate, "invalid_form"},
	}

	for label, test := range cases {
		recorder := fixture.post("/settings/portal/users", test.form)

		if redirectTo(recorder) != "/settings?problem="+test.want+"#portal" {
			t.Errorf("%s: location = %q", label, redirectTo(recorder))
		}
	}

	if fixture.admin.count("create") != 0 {
		t.Fatal("the daemon was asked to create a user from a bad form")
	}
}

func TestUserErrorsAreShownWithFixedMessages(t *testing.T) {
	cases := map[string]string{
		localcontrol.ErrorUserExists:        "user_exists",
		localcontrol.ErrorInvalidUser:       "invalid_user",
		localcontrol.ErrorTooManyUsers:      "too_many_users",
		localcontrol.ErrorUserNotFound:      "user_not_found",
		localcontrol.ErrorForbidden:         "forbidden",
		localcontrol.ErrorInternal:          "unavailable",
		localcontrol.ErrorPortalUnavailable: "unavailable",
	}

	for code, want := range cases {
		fixture := newPortalFixture(t)
		fixture.admin.changeErr = &localcontrol.RemoteError{Code: code, Message: "secret detail /etc/shadow"}

		recorder := fixture.post("/settings/portal/users", url.Values{
			"name": {"carol"}, "role": {"viewer"}, "password": {adminPassword}, "confirm": {adminPassword},
		})

		if redirectTo(recorder) != "/settings?problem="+want+"#portal" {
			t.Errorf("code %q: location = %q", code, redirectTo(recorder))
		}

		if strings.Contains(redirectTo(recorder), "shadow") {
			t.Errorf("code %q: a daemon message reached the redirect", code)
		}
	}

	// A transport error is "unavailable" too.
	fixture := newPortalFixture(t)
	fixture.admin.changeErr = localcontrol.ErrControlUnavailable

	recorder := fixture.post("/settings/portal/users", url.Values{
		"name": {"carol"}, "role": {"viewer"}, "password": {adminPassword}, "confirm": {adminPassword},
	})

	if redirectTo(recorder) != "/settings?problem=unavailable#portal" {
		t.Fatalf("location = %q", redirectTo(recorder))
	}
}

func TestPasswordsAreNeverShownBack(t *testing.T) {
	fixture := newPortalFixture(t)

	responses := []*httptest.ResponseRecorder{
		fixture.post("/settings/portal/users", url.Values{"name": {"carol"}, "role": {"viewer"}, "password": {adminPassword}, "confirm": {adminPassword}}),
		fixture.post("/settings/portal/users", url.Values{"name": {"carol"}, "role": {"viewer"}, "password": {adminPassword}, "confirm": {"different"}}),
		fixture.post("/settings/portal/users/alice/password", url.Values{"password": {adminPassword}, "confirm": {adminPassword}}),
		fixture.get("/settings"),
	}

	for _, recorder := range responses {
		if strings.Contains(recorder.Body.String(), adminPassword) ||
			strings.Contains(redirectTo(recorder), adminPassword) ||
			strings.Contains(redirectTo(recorder), "carol") ||
			strings.Contains(strings.Join(recorder.Header().Values("Set-Cookie"), ""), adminPassword) {
			t.Fatal("a password or a typed value was shown back")
		}
	}
}

func TestChangingAUserEndsTheirSessions(t *testing.T) {
	cases := []struct {
		label  string
		path   string
		form   url.Values
		op     string
		notice string
	}{
		{"password", "/settings/portal/users/alice/password", url.Values{"password": {adminPassword}, "confirm": {adminPassword}}, "set_password", "password_set"},
		{"role", "/settings/portal/users/alice/role", url.Values{"role": {"viewer"}}, "set_role", "role_set"},
		{"disable", "/settings/portal/users/alice/disabled", url.Values{"disabled": {"1"}}, "set_disabled", "user_disabled"},
		{"enable", "/settings/portal/users/alice/disabled", url.Values{"disabled": {"0"}}, "set_disabled", "user_enabled"},
		{"delete", "/settings/portal/users/alice/delete", url.Values{"confirm": {"alice"}}, "delete", "user_deleted"},
	}

	for _, test := range cases {
		fixture := newPortalFixture(t)

		recorder := fixture.post(test.path, test.form)

		if recorder.Code != http.StatusSeeOther || redirectTo(recorder) != "/settings?notice="+test.notice+"#portal" {
			t.Errorf("%s: status = %d, location = %q", test.label, recorder.Code, redirectTo(recorder))
		}

		if call, ok := fixture.admin.last(test.op); !ok || call.args[0] != "alice" {
			t.Errorf("%s: call = %+v", test.label, call)
		}

		if revoked := fixture.runtime.revocations(); len(revoked) != 1 || revoked[0] != "alice" {
			t.Errorf("%s: revoked = %v; the user's sessions were not ended", test.label, revoked)
		}
	}
}

func TestAFailedChangeDoesNotEndSessions(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.admin.changeErr = &localcontrol.RemoteError{Code: localcontrol.ErrorUserNotFound}

	recorder := fixture.post("/settings/portal/users/alice/role", url.Values{"role": {"viewer"}})

	if redirectTo(recorder) != "/settings?problem=user_not_found#portal" {
		t.Fatalf("location = %q", redirectTo(recorder))
	}

	if len(fixture.runtime.revocations()) != 0 {
		t.Fatal("sessions were ended although the change failed")
	}

	// A change that was applied but may not be durable still ends sessions.
	fixture = newPortalFixture(t)
	fixture.admin.changeErr = &localcontrol.RemoteError{Code: localcontrol.ErrorUserDurability}

	recorder = fixture.post("/settings/portal/users/alice/disabled", url.Values{"disabled": {"1"}})
	if redirectTo(recorder) != "/settings?notice=durability#portal" || len(fixture.runtime.revocations()) != 1 {
		t.Fatalf("durability: %q, revoked %v", redirectTo(recorder), fixture.runtime.revocations())
	}
}

func TestUserFormsRejectBadInputBeforeTheDaemon(t *testing.T) {
	fixture := newPortalFixture(t)

	cases := []struct {
		label string
		path  string
		form  url.Values
		want  string
	}{
		{"password mismatch", "/settings/portal/users/alice/password", url.Values{"password": {adminPassword}, "confirm": {"x"}}, "passwords_differ"},
		{"password extra", "/settings/portal/users/alice/password", url.Values{"password": {adminPassword}, "confirm": {adminPassword}, "role": {"editor"}}, "invalid_form"},
		{"role missing", "/settings/portal/users/alice/role", url.Values{}, "invalid_form"},
		{"role extra", "/settings/portal/users/alice/role", url.Values{"role": {"viewer"}, "name": {"bob"}}, "invalid_form"},
		{"disabled word", "/settings/portal/users/alice/disabled", url.Values{"disabled": {"yes"}}, "invalid_form"},
		{"disabled twice", "/settings/portal/users/alice/disabled", url.Values{"disabled": {"1", "0"}}, "invalid_form"},
		{"delete wrong name", "/settings/portal/users/alice/delete", url.Values{"confirm": {"bob"}}, "confirm_mismatch"},
		{"delete case", "/settings/portal/users/alice/delete", url.Values{"confirm": {"ALICE"}}, "confirm_mismatch"},
		{"delete empty", "/settings/portal/users/alice/delete", url.Values{"confirm": {""}}, "confirm_mismatch"},
		{"delete padded", "/settings/portal/users/alice/delete", url.Values{"confirm": {"alice "}}, "confirm_mismatch"},
	}

	for _, test := range cases {
		recorder := fixture.post(test.path, test.form)

		if redirectTo(recorder) != "/settings?problem="+test.want+"#portal" {
			t.Errorf("%s: location = %q", test.label, redirectTo(recorder))
		}
	}

	for _, operation := range []string{"set_password", "set_role", "set_disabled", "delete"} {
		if fixture.admin.count(operation) != 0 {
			t.Errorf("%s reached the daemon with a bad form", operation)
		}
	}

	if len(fixture.runtime.revocations()) != 0 {
		t.Fatal("a rejected form ended sessions")
	}
}

func TestOnlyFixedNoticesAndProblemsAreShown(t *testing.T) {
	fixture := newPortalFixture(t)

	body := fixture.get("/settings?notice=user_created&problem=forbidden").Body.String()
	if !strings.Contains(body, "User created.") || !strings.Contains(body, "may not change the portal") {
		t.Fatal("a known notice or problem was not shown")
	}

	for _, path := range []string{
		"/settings?notice=%3Cscript%3Ealert(1)%3C/script%3E&problem=%3Cimg%20src=x%3E",
		"/settings?notice=<b>bold</b>",
		"/settings?problem=carol",
	} {
		page := fixture.get(path).Body.String()

		if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x") || strings.Contains(page, "<b>bold</b>") {
			t.Errorf("%s: query text was reflected", path)
		}

		if strings.Contains(page, `class="aamm-portal-notice"`) || strings.Contains(page, `class="aamm-portal-problem" role="alert"`) {
			t.Errorf("%s: a message was shown for an unknown key", path)
		}
	}
}

func TestUserNamesInThePageAreEscaped(t *testing.T) {
	fixture := newPortalFixture(t)
	fixture.admin.users = []localcontrol.PortalUserResult{{Name: `<script>alert(1)</script>"x`, Role: "viewer"}}

	body := fixture.get("/settings").Body.String()

	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("a user name was inserted as markup")
	}
}

func TestPortalFormsHaveABodyLimit(t *testing.T) {
	fixture := newPortalFixture(t)

	big := url.Values{"name": {"carol"}, "role": {"viewer"}, "password": {strings.Repeat("a", int(maxMutationBodyBytes)+10)}, "confirm": {"x"}}

	recorder := fixture.post("/settings/portal/users", big)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", recorder.Code)
	}

	if fixture.admin.total() != 0 {
		t.Fatal("an oversized form reached the daemon")
	}
}

func TestPasswordFieldsAreNotAutofilledOrReflected(t *testing.T) {
	fixture := newPortalFixture(t)

	body := fixture.get("/settings").Body.String()

	if strings.Contains(body, `type="password" name="password" value=`) {
		t.Fatal("a password field has a preset value")
	}

	if !strings.Contains(body, `autocomplete="new-password"`) {
		t.Fatal("password fields do not use new-password autocomplete")
	}
}

func TestPortalViewHostHandling(t *testing.T) {
	cases := map[string]string{
		"node.local.mesh:11313": "node.local.mesh",
		"node.local.mesh":       "node.local.mesh",
		"10.1.2.3:80":           "10.1.2.3",
		"[fe80::1]:80":          "[fe80::1]",
		"":                      "",
	}

	for host, want := range cases {
		if got := hostWithoutPort(host); got != want {
			t.Errorf("hostWithoutPort(%q) = %q; want %q", host, got, want)
		}
	}
}
