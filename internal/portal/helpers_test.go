package portal

import (
	"context"
	"crypto/rand"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/auditidentity"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
	"github.com/k2exe/aamm-ng/internal/minihttp/httptest"
)

const (
	testHost     = "portal.test"
	testPassword = "correct horse battery"
	testIP       = "192.0.2.10"
)

type call struct {
	op          string
	args        []string
	identity    auditidentity.Identity
	hasIdentity bool
}

type fakeBackend struct {
	mu      sync.Mutex
	calls   []call
	entries map[string]localcontrol.EntryResult
	failure error

	users map[string]localcontrol.PortalLoginResult

	loginFailure error
	loginGate    chan struct{}
	loginEntered chan struct{}
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		entries: map[string]localcontrol.EntryResult{
			"all": {Target: "all", Kind: "managed", Message: "Net at 7 PM", Size: 11},
		},
		users: map[string]localcontrol.PortalLoginResult{
			"alice": {Name: "alice", Role: "editor"},
			"bob":   {Name: "bob", Role: "viewer"},
		},
	}
}

func (backend *fakeBackend) record(ctx context.Context, op string, args ...string) {
	identity, ok := auditidentity.FromContext(ctx)

	backend.mu.Lock()
	defer backend.mu.Unlock()

	backend.calls = append(backend.calls, call{op, args, identity, ok})
}

func (backend *fakeBackend) count(op string) int {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	total := 0

	for _, entry := range backend.calls {
		if entry.op == op {
			total++
		}
	}

	return total
}

func (backend *fakeBackend) changes() []call {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	var result []call

	for _, entry := range backend.calls {
		switch entry.op {
		case "create", "write", "convert", "delete":
			result = append(result, entry)
		}
	}

	return result
}

func (backend *fakeBackend) last(op string) (call, bool) {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	for index := len(backend.calls) - 1; index >= 0; index-- {
		if backend.calls[index].op == op {
			return backend.calls[index], true
		}
	}

	return call{}, false
}

func (backend *fakeBackend) PortalLogin(
	ctx context.Context,
	name, password, sourceIP string,
) (localcontrol.PortalLoginResult, error) {
	backend.record(ctx, "login", name, password, sourceIP)

	if backend.loginEntered != nil {
		backend.loginEntered <- struct{}{}
	}

	if backend.loginGate != nil {
		<-backend.loginGate
	}

	if backend.loginFailure != nil {
		return localcontrol.PortalLoginResult{}, backend.loginFailure
	}

	result, ok := backend.users[name]
	if !ok || password != testPassword {
		return localcontrol.PortalLoginResult{}, &localcontrol.RemoteError{
			Code:    localcontrol.ErrorInvalidCredentials,
			Message: "invalid user name or password",
		}
	}

	return result, nil
}

func (backend *fakeBackend) List(ctx context.Context) (localcontrol.ListResult, error) {
	backend.record(ctx, "list")

	if backend.failure != nil {
		return localcontrol.ListResult{}, backend.failure
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	result := localcontrol.ListResult{}

	for _, entry := range backend.entries {
		result.Entries = append(result.Entries, entry)
	}

	return result, nil
}

func (backend *fakeBackend) Read(ctx context.Context, target string) (localcontrol.EntryResult, error) {
	backend.record(ctx, "read", target)

	if backend.failure != nil {
		return localcontrol.EntryResult{}, backend.failure
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	entry, ok := backend.entries[target]
	if !ok {
		return localcontrol.EntryResult{}, &localcontrol.RemoteError{
			Code: localcontrol.ErrorNotFound, Message: "not found",
		}
	}

	return entry, nil
}

func (backend *fakeBackend) Create(ctx context.Context, target, message string) (localcontrol.CreateResult, error) {
	backend.record(ctx, "create", target, message)

	if backend.failure != nil {
		return localcontrol.CreateResult{}, backend.failure
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	backend.entries[strings.ToLower(target)] = localcontrol.EntryResult{
		Target: strings.ToLower(target), Kind: "managed", Message: message, Size: int64(len(message)),
	}

	return localcontrol.CreateResult{Target: target, Kind: "managed"}, nil
}

func (backend *fakeBackend) Write(ctx context.Context, target, message string) (localcontrol.WriteResult, error) {
	backend.record(ctx, "write", target, message)

	if backend.failure != nil {
		return localcontrol.WriteResult{}, backend.failure
	}

	return localcontrol.WriteResult{Target: target, Kind: "managed"}, nil
}

func (backend *fakeBackend) Convert(ctx context.Context, target, message string) (localcontrol.ConvertResult, error) {
	backend.record(ctx, "convert", target, message)

	if backend.failure != nil {
		return localcontrol.ConvertResult{}, backend.failure
	}

	return localcontrol.ConvertResult{Target: target, Kind: "managed", BackupName: "backup"}, nil
}

func (backend *fakeBackend) Delete(ctx context.Context, target string) (localcontrol.DeleteResult, error) {
	backend.record(ctx, "delete", target)

	if backend.failure != nil {
		return localcontrol.DeleteResult{}, backend.failure
	}

	return localcontrol.DeleteResult{Target: target, BackupName: "backup"}, nil
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()

	return clock.t
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()

	clock.t = clock.t.Add(duration)
}

type env struct {
	t       *testing.T
	handler *Handler
	backend *fakeBackend
	clock   *fakeClock
}

func newEnv(t *testing.T) *env {
	t.Helper()

	return newEnvWithNodes(t, nil)
}

func newEnvWithNodes(t *testing.T, nodes NodeLister) *env {
	t.Helper()

	clock := &fakeClock{t: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	backend := newFakeBackend()

	handler, err := NewHandler(backend, nodes, Options{
		Random: rand.Reader,
		Now:    clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	return &env{t: t, handler: handler, backend: backend, clock: clock}
}

type requestOption func(*http.Request)

func newRequest(
	method string,
	path string,
	form url.Values,
	options ...requestOption,
) *http.Request {
	var request *http.Request

	if form != nil {
		request = httptest.NewRequest(method, "http://"+testHost+path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "http://"+testHost)
	} else {
		request = httptest.NewRequest(method, "http://"+testHost+path, nil)
	}

	request.Host = testHost
	request.RemoteAddr = testIP + ":50000"

	for _, option := range options {
		option(request)
	}

	return request
}

func withCookie(token string) requestOption {
	return func(request *http.Request) {
		request.Header.Set("Cookie", CookieName+"="+token)
	}
}

func withIP(address string) requestOption {
	return func(request *http.Request) {
		request.RemoteAddr = address + ":50000"
	}
}

func withHeader(name, value string) requestOption {
	return func(request *http.Request) {
		request.Header.Set(name, value)
	}
}

func withoutHeader(name string) requestOption {
	return func(request *http.Request) {
		request.Header.Del(name)
	}
}

func (e *env) do(request *http.Request) *httptest.ResponseRecorder {
	e.t.Helper()

	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)

	return recorder
}

var (
	cookiePattern = regexp.MustCompile(`^` + CookieName + `=([0-9a-f]+);`)
	csrfPattern   = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)
)

func tokenFrom(recorder *httptest.ResponseRecorder) string {
	for _, value := range recorder.Header().Values("Set-Cookie") {
		if match := cookiePattern.FindStringSubmatch(value); match != nil {
			return match[1]
		}
	}

	return ""
}

func csrfFrom(body string) string {
	if match := csrfPattern.FindStringSubmatch(body); match != nil {
		return match[1]
	}

	return ""
}

type login struct {
	token string
	csrf  string
	ip    string
}

// loginAs signs in and returns the cookie and the page CSRF token.
func (e *env) loginAs(name string, options ...requestOption) login {
	e.t.Helper()

	form := url.Values{"name": {name}, "password": {testPassword}}

	recorder := e.do(newRequest("POST", "/login", form, options...))
	if recorder.Code != http.StatusSeeOther {
		e.t.Fatalf("login as %s: status = %d\n%s", name, recorder.Code, recorder.Body)
	}

	token := tokenFrom(recorder)
	if token == "" {
		e.t.Fatal("login set no session cookie")
	}

	ip := testIP

	probe := newRequest("GET", "/", nil, append(options, withCookie(token))...)
	page := e.do(probe)

	csrf := csrfFrom(page.Body.String())
	if csrf == "" {
		e.t.Fatalf("no CSRF token on the home page:\n%s", page.Body)
	}

	return login{token: token, csrf: csrf, ip: ip}
}

func (s login) post(path string, form url.Values, options ...requestOption) *http.Request {
	if form == nil {
		form = url.Values{}
	}

	if form.Get("csrf") == "" && form["csrf"] == nil {
		form.Set("csrf", s.csrf)
	}

	return newRequest("POST", path, form, append(options, withCookie(s.token))...)
}

func (s login) get(path string, options ...requestOption) *http.Request {
	return newRequest("GET", path, nil, append(options, withCookie(s.token))...)
}

func location(recorder *httptest.ResponseRecorder) string {
	return recorder.Header().Get("Location")
}

func httpDo(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder
}
