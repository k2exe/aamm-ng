package portal

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

func TestLoginPageIsServedWithoutAnAccount(t *testing.T) {
	e := newEnv(t)

	recorder := e.do(newRequest("GET", "/", nil))

	// AREDN's service check accepts only 200 and 401.
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}

	body := recorder.Body.String()

	if !strings.Contains(body, `action="/login"`) || strings.Contains(body, `name="csrf"`) {
		t.Fatalf("unexpected login page:\n%s", body)
	}

	if len(e.backend.calls) != 0 {
		t.Fatalf("the daemon was called without a login: %+v", e.backend.calls)
	}
}

func TestProtectedRoutesRequireALogin(t *testing.T) {
	e := newEnv(t)

	post := url.Values{"csrf": {"x"}, "target": {"all"}, "message": {"hi"}, "confirm": {"all"}}

	requests := map[string]*http.Request{
		"GET /alerts/new":          newRequest("GET", "/alerts/new", nil),
		"GET /alerts/all":          newRequest("GET", "/alerts/all", nil),
		"POST /alerts/new":         newRequest("POST", "/alerts/new", post),
		"POST /alerts/all":         newRequest("POST", "/alerts/all", post),
		"POST /alerts/all/delete":  newRequest("POST", "/alerts/all/delete", post),
		"POST /alerts/all/convert": newRequest("POST", "/alerts/all/convert", post),
		"POST /logout":             newRequest("POST", "/logout", post),
		"bad cookie":               newRequest("GET", "/alerts/all", nil, withCookie("nonsense")),
		"short token":              newRequest("GET", "/alerts/all", nil, withCookie(strings.Repeat("a", 63))),
		"unknown token":            newRequest("GET", "/alerts/all", nil, withCookie(strings.Repeat("a", 64))),
	}

	for label, request := range requests {
		recorder := e.do(request)

		if recorder.Code != http.StatusSeeOther || location(recorder) != "/" {
			t.Errorf("%s: status = %d, location = %q; want 303 to /", label, recorder.Code, location(recorder))
		}
	}

	if len(e.backend.calls) != 0 {
		t.Fatalf("the daemon was called without a login: %+v", e.backend.calls)
	}
}

func TestMethodsAndUnknownPaths(t *testing.T) {
	e := newEnv(t)
	session := e.loginAs("alice")

	notAllowed := []struct {
		method, path string
	}{
		{"PUT", "/"}, {"DELETE", "/"}, {"POST", "/"},
		{"GET", "/login"}, {"PUT", "/login"},
		{"GET", "/logout"}, {"HEAD", "/logout"},
		{"GET", "/alerts/all/delete"}, {"GET", "/alerts/all/convert"},
		{"PUT", "/alerts/all"}, {"DELETE", "/alerts/all"},
		{"POST", "/portal.css"}, {"PUT", "/alerts/new"},
	}

	for _, test := range notAllowed {
		recorder := e.do(newRequest(test.method, test.path, nil, withCookie(session.token)))

		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") == "" {
			t.Errorf("%s %s: status = %d, Allow = %q", test.method, test.path, recorder.Code, recorder.Header().Get("Allow"))
		}
	}

	// The portal has no settings, no user management and no API.
	for _, path := range []string{
		"/settings", "/settings/portal", "/portal", "/portal/users", "/users",
		"/api/local-nodes", "/admin", "/alerts", "/alerts/", "/login/", "/robots.txt",
	} {
		recorder := e.do(newRequest("GET", path, nil, withCookie(session.token)))

		if recorder.Code != http.StatusNotFound && recorder.Code != http.StatusMovedPermanently {
			t.Errorf("GET %s: status = %d; want 404", path, recorder.Code)
		}
	}

	for _, path := range []string{"/settings", "/settings/portal/users", "/users/alice/delete"} {
		form := url.Values{"csrf": {session.csrf}, "name": {"mallory"}, "role": {"editor"}, "password": {"x"}}

		recorder := e.do(newRequest("POST", path, form, withCookie(session.token)))

		if recorder.Code != http.StatusNotFound {
			t.Errorf("POST %s: status = %d; want 404", path, recorder.Code)
		}
	}
}

func TestLoginSetsAHardenedSessionCookie(t *testing.T) {
	e := newEnv(t)

	recorder := e.do(newRequest("POST", "/login", url.Values{"name": {"alice"}, "password": {testPassword}}))

	if recorder.Code != http.StatusSeeOther || location(recorder) != "/" {
		t.Fatalf("status = %d, location = %q", recorder.Code, location(recorder))
	}

	cookies := recorder.Header().Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie headers = %v", cookies)
	}

	cookie := cookies[0]

	pattern := regexp.MustCompile(`^aamm_portal=[0-9a-f]{64}; Path=/; HttpOnly; SameSite=Strict$`)
	if !pattern.MatchString(cookie) {
		t.Fatalf("cookie = %q", cookie)
	}

	for _, banned := range []string{"Domain", "Expires", "Max-Age", "SameSite=Lax", "SameSite=None"} {
		if strings.Contains(cookie, banned) {
			t.Errorf("cookie contains %q: %s", banned, cookie)
		}
	}
}

func TestSessionTokensAreUnique(t *testing.T) {
	e := newEnv(t)

	tokens := map[string]bool{}
	csrfs := map[string]bool{}

	for index := 0; index < 20; index++ {
		session := e.loginAs("alice", withIP(fmt.Sprintf("192.0.2.%d", 20+index)))

		if tokens[session.token] || csrfs[session.csrf] {
			t.Fatal("a token was issued twice")
		}

		tokens[session.token] = true
		csrfs[session.csrf] = true

		if session.token == session.csrf {
			t.Fatal("the CSRF token equals the session token")
		}
	}
}

func TestFailedLoginsAreGenericAndSetNoCookie(t *testing.T) {
	e := newEnv(t)

	cases := map[string]url.Values{
		"wrong password": {"name": {"alice"}, "password": {"wrong password"}},
		"unknown user":   {"name": {"mallory"}, "password": {testPassword}},
		"empty name":     {"name": {""}, "password": {testPassword}},
		"empty password": {"name": {"alice"}, "password": {""}},
		"missing fields": {},
	}

	var first string

	for label, form := range cases {
		recorder := e.do(newRequest("POST", "/login", form, withIP("192.0.2."+fmt.Sprint(100+len(label)))))

		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d", label, recorder.Code)
		}

		if tokenFrom(recorder) != "" || len(recorder.Header().Values("Set-Cookie")) != 0 {
			t.Errorf("%s: a cookie was set", label)
		}

		message := regexp.MustCompile(`<p class="error"[^>]*>([^<]*)</p>`).FindStringSubmatch(recorder.Body.String())
		if message == nil {
			t.Fatalf("%s: no error message", label)
		}

		if first == "" {
			first = message[1]
		} else if message[1] != first {
			t.Errorf("%s: message %q differs from %q", label, message[1], first)
		}
	}
}

func TestServiceFailureDuringLoginIsNotCountedAgainstTheUser(t *testing.T) {
	e := newEnv(t)
	e.backend.loginFailure = localcontrol.ErrControlUnavailable

	for index := 0; index < 8; index++ {
		recorder := e.do(newRequest("POST", "/login", url.Values{"name": {"alice"}, "password": {testPassword}}))

		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: status = %d", index, recorder.Code)
		}

		if tokenFrom(recorder) != "" {
			t.Fatal("a session was created")
		}

		if strings.Contains(recorder.Body.String(), "unavailable") && strings.Contains(recorder.Body.String(), "socket") {
			t.Fatal("the response leaks an internal error")
		}
	}

	if size := e.handler.limiter.Size(); size != 0 {
		t.Fatalf("limiter tracks %d addresses after service failures", size)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)

	wrong := url.Values{"name": {"alice"}, "password": {"wrong password"}}

	for attempt := 1; attempt <= 5; attempt++ {
		recorder := e.do(newRequest("POST", "/login", wrong))

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d", attempt, recorder.Code)
		}
	}

	calls := e.backend.count("login")

	// The sixth attempt is refused before any password is checked, even with
	// the right password.
	for _, form := range []url.Values{wrong, {"name": {"alice"}, "password": {testPassword}}} {
		recorder := e.do(newRequest("POST", "/login", form))

		if recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d; want 429", recorder.Code)
		}

		retry := recorder.Header().Get("Retry-After")
		if retry == "" || strings.Trim(retry, "0123456789") != "" {
			t.Fatalf("Retry-After = %q", retry)
		}

		if tokenFrom(recorder) != "" {
			t.Fatal("a session was created while locked")
		}
	}

	if e.backend.count("login") != calls {
		t.Fatal("the daemon checked a password for a locked address")
	}

	// Another address is not affected.
	other := e.do(newRequest("POST", "/login", wrong, withIP("192.0.2.77")))
	if other.Code != http.StatusUnauthorized {
		t.Fatalf("other address status = %d", other.Code)
	}

	// After the lock, a good login works and clears the record.
	e.clock.Advance(61 * time.Second)

	good := e.do(newRequest("POST", "/login", url.Values{"name": {"alice"}, "password": {testPassword}}))
	if good.Code != http.StatusSeeOther {
		t.Fatalf("login after the lock: status = %d", good.Code)
	}

	for index := 0; index < 4; index++ {
		if recorder := e.do(newRequest("POST", "/login", wrong)); recorder.Code != http.StatusUnauthorized {
			t.Fatalf("the record was not cleared: status = %d", recorder.Code)
		}
	}
}

func TestRotatingHeadersDoesNotEvadeTheLimiter(t *testing.T) {
	e := newEnv(t)

	wrong := url.Values{"name": {"alice"}, "password": {"wrong password"}}

	for attempt := 0; attempt < 5; attempt++ {
		e.do(newRequest("POST", "/login", wrong,
			withHeader("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", attempt)),
			withHeader("X-Real-IP", fmt.Sprintf("198.51.100.%d", attempt)),
			withHeader("X-AAMM-Remote-Addr", fmt.Sprintf("10.0.0.%d", attempt)),
			withHeader("Forwarded", fmt.Sprintf("for=203.0.113.%d", attempt)),
		))
	}

	recorder := e.do(newRequest("POST", "/login", wrong, withHeader("X-Forwarded-For", "203.0.113.250")))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d; the limiter followed a header", recorder.Code)
	}

	for _, entry := range e.backend.calls {
		if entry.op == "login" && entry.args[2] != testIP {
			t.Fatalf("login used source %q; want the peer %q", entry.args[2], testIP)
		}
	}
}

func TestSourceAddressIsTheTCPPeer(t *testing.T) {
	e := newEnv(t)

	spoof := []requestOption{
		withHeader("X-Forwarded-For", "203.0.113.9"),
		withHeader("X-AAMM-Remote-Addr", "198.51.100.1"),
	}

	session := e.loginAs("alice", spoof...)

	if _, err := e.do(session.post("/alerts/new", url.Values{"target": {"all2"}, "message": {"hello"}}, spoof...)), error(nil); err != nil {
		t.Fatal(err)
	}

	recorder := e.do(session.post("/alerts/new", url.Values{"target": {"node-a"}, "message": {"hello"}}, spoof...))
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", recorder.Code)
	}

	change, ok := e.backend.last("create")
	if !ok || change.identity.SourceIP != testIP {
		t.Fatalf("identity = %+v; want the peer address", change.identity)
	}

	// An IPv4-mapped peer address is normalised.
	mapped := newRequest("GET", "/", nil, withCookie(session.token))
	mapped.RemoteAddr = "[::ffff:192.0.2.10]:50000"

	if page := e.do(mapped); !strings.Contains(page.Body.String(), "alice") {
		t.Fatal("a mapped address did not match the session")
	}

	// An unparseable peer address is never trusted.
	bogus := newRequest("GET", "/", nil, withCookie(session.token))
	bogus.RemoteAddr = "not-an-address"

	if page := e.do(bogus); strings.Contains(page.Body.String(), "alice") {
		t.Fatal("a request with a bad peer address got a session")
	}

	badLogin := newRequest("POST", "/login", url.Values{"name": {"alice"}, "password": {testPassword}})
	badLogin.RemoteAddr = "garbage"

	if recorder := e.do(badLogin); recorder.Code != http.StatusBadRequest {
		t.Fatalf("login with a bad peer address: status = %d", recorder.Code)
	}
}

func TestLoginDoesNotFixASession(t *testing.T) {
	e := newEnv(t)

	attacker := strings.Repeat("ab", 32)

	recorder := e.do(newRequest("POST", "/login",
		url.Values{"name": {"alice"}, "password": {testPassword}}, withCookie(attacker)))

	token := tokenFrom(recorder)
	if token == "" || token == attacker {
		t.Fatalf("the session token was not replaced: %q", token)
	}

	if page := e.do(newRequest("GET", "/", nil, withCookie(attacker))); strings.Contains(page.Body.String(), "alice") {
		t.Fatal("the attacker's token became a session")
	}

	// A login from an existing session ends the old one.
	first := e.loginAs("alice")

	second := e.do(newRequest("POST", "/login",
		url.Values{"name": {"alice"}, "password": {testPassword}}, withCookie(first.token)))

	if tokenFrom(second) == first.token {
		t.Fatal("the token was reused")
	}

	if recorder := e.do(first.get("/alerts/all")); recorder.Code != http.StatusSeeOther {
		t.Fatalf("the old session still works: status = %d", recorder.Code)
	}
}

func TestOriginChecksOnLogin(t *testing.T) {
	e := newEnv(t)

	form := url.Values{"name": {"alice"}, "password": {testPassword}}

	rejected := map[string][]requestOption{
		"no origin or referer":     {withoutHeader("Origin")},
		"other origin":             {withHeader("Origin", "http://evil.test")},
		"https origin":             {withHeader("Origin", "https://"+testHost)},
		"null origin":              {withHeader("Origin", "null")},
		"origin with port":         {withHeader("Origin", "http://"+testHost+":8080")},
		"origin as prefix":         {withHeader("Origin", "http://"+testHost+".evil.test")},
		"other referer":            {withoutHeader("Origin"), withHeader("Referer", "http://evil.test/login")},
		"https referer":            {withoutHeader("Origin"), withHeader("Referer", "https://"+testHost+"/")},
		"garbage referer":          {withoutHeader("Origin"), withHeader("Referer", "::::")},
		"origin wins over referer": {withHeader("Origin", "http://evil.test"), withHeader("Referer", "http://"+testHost+"/")},
	}

	for label, options := range rejected {
		recorder := e.do(newRequest("POST", "/login", form, options...))

		if recorder.Code != http.StatusForbidden || tokenFrom(recorder) != "" {
			t.Errorf("%s: status = %d", label, recorder.Code)
		}
	}

	if e.backend.count("login") != 0 {
		t.Fatal("the daemon checked a login that failed the origin check")
	}

	accepted := map[string][]requestOption{
		"same origin":                   nil,
		"same origin, different case":   {withHeader("Origin", "http://PORTAL.test")},
		"referer when origin is absent": {withoutHeader("Origin"), withHeader("Referer", "http://"+testHost+"/")},
	}

	for label, options := range accepted {
		recorder := e.do(newRequest("POST", "/login", form, options...))

		if recorder.Code != http.StatusSeeOther {
			t.Errorf("%s: status = %d", label, recorder.Code)
		}
	}
}

func TestLoginInputLimits(t *testing.T) {
	e := newEnv(t)

	cases := map[string]url.Values{
		"long name":      {"name": {strings.Repeat("a", maxNameBytes+1)}, "password": {testPassword}},
		"long password":  {"name": {"alice"}, "password": {strings.Repeat("a", maxPasswordBytes+1)}},
		"duplicate name": {"name": {"alice", "bob"}, "password": {testPassword}},
		"duplicate pass": {"name": {"alice"}, "password": {testPassword, testPassword}},
	}

	for label, form := range cases {
		recorder := e.do(newRequest("POST", "/login", form, withIP("192.0.2."+fmt.Sprint(30+len(label)))))

		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d", label, recorder.Code)
		}
	}

	if e.backend.count("login") != 0 {
		t.Fatal("the daemon was asked to check an invalid login")
	}

	// A body over the size limit is refused.
	big := url.Values{"name": {"alice"}, "password": {strings.Repeat("a", maxFormBytes+10)}}

	if recorder := e.do(newRequest("POST", "/login", big, withIP("192.0.2.200"))); recorder.Code != http.StatusRequestEntityTooBig {
		t.Fatalf("oversized body: status = %d", recorder.Code)
	}

	// Anything but a urlencoded form carries no fields.
	plain := newRequest("POST", "/login", url.Values{"name": {"alice"}, "password": {testPassword}},
		withHeader("Content-Type", "text/plain"), withIP("192.0.2.201"))

	if recorder := e.do(plain); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("text/plain body: status = %d", recorder.Code)
	}
}

func TestOnlyOneLoginCheckRunsAtATime(t *testing.T) {
	e := newEnv(t)

	e.backend.loginGate = make(chan struct{})
	e.backend.loginEntered = make(chan struct{}, 4)

	done := make(chan *int, 1)

	go func() {
		recorder := e.do(newRequest("POST", "/login",
			url.Values{"name": {"alice"}, "password": {testPassword}}, withIP("192.0.2.50")))

		code := recorder.Code
		done <- &code
	}()

	<-e.backend.loginEntered

	busy := e.do(newRequest("POST", "/login",
		url.Values{"name": {"bob"}, "password": {testPassword}}, withIP("192.0.2.51")))

	if busy.Code != http.StatusServiceUnavailable || busy.Header().Get("Retry-After") == "" {
		t.Fatalf("second login: status = %d", busy.Code)
	}

	if e.backend.count("login") != 1 {
		t.Fatal("a second password check started")
	}

	close(e.backend.loginGate)

	if code := <-done; *code != http.StatusSeeOther {
		t.Fatalf("first login: status = %d", *code)
	}

	// The slot is free again.
	e.backend.loginGate = nil

	if recorder := e.do(newRequest("POST", "/login",
		url.Values{"name": {"bob"}, "password": {testPassword}}, withIP("192.0.2.51"))); recorder.Code != http.StatusSeeOther {
		t.Fatalf("login after the slot was released: status = %d", recorder.Code)
	}
}

func TestSessionExpiresWhenIdle(t *testing.T) {
	e := newEnv(t)
	session := e.loginAs("alice")

	e.clock.Advance(29 * time.Minute)

	if recorder := e.do(session.get("/")); !strings.Contains(recorder.Body.String(), "Alerts") {
		t.Fatal("the session ended too early")
	}

	// Activity extends the idle time.
	e.clock.Advance(29 * time.Minute)

	if recorder := e.do(session.get("/")); !strings.Contains(recorder.Body.String(), "Alerts") {
		t.Fatal("activity did not extend the session")
	}

	e.clock.Advance(31 * time.Minute)

	recorder := e.do(session.get("/"))
	if !strings.Contains(recorder.Body.String(), "Sign in") || strings.Contains(recorder.Body.String(), "alice") {
		t.Fatal("an idle session still works")
	}

	if e.handler.sessions.Count() != 0 {
		t.Fatal("the expired session was kept")
	}
}

func TestSessionHasAMaximumLifetime(t *testing.T) {
	e := newEnv(t)
	session := e.loginAs("alice")

	for elapsed := time.Duration(0); elapsed < 8*time.Hour; elapsed += 20 * time.Minute {
		e.clock.Advance(20 * time.Minute)

		if elapsed+20*time.Minute > 8*time.Hour {
			break
		}

		if recorder := e.do(session.get("/")); !strings.Contains(recorder.Body.String(), "alice") {
			t.Fatalf("the session ended early, after %v", elapsed)
		}
	}

	e.clock.Advance(30 * time.Minute)

	if recorder := e.do(session.get("/")); strings.Contains(recorder.Body.String(), "alice") {
		t.Fatal("a session outlived the maximum lifetime")
	}
}

func TestSessionIsBoundToItsSourceAddress(t *testing.T) {
	e := newEnv(t)
	session := e.loginAs("alice")

	stolen := e.do(newRequest("GET", "/", nil, withCookie(session.token), withIP("192.0.2.99")))
	if strings.Contains(stolen.Body.String(), "alice") {
		t.Fatal("the cookie worked from another address")
	}

	if recorder := e.do(newRequest("POST", "/alerts/new",
		url.Values{"csrf": {session.csrf}, "target": {"node-a"}, "message": {"x"}},
		withCookie(session.token), withIP("192.0.2.99"))); recorder.Code != http.StatusSeeOther || location(recorder) != "/" {
		t.Fatalf("a post from another address: status = %d", recorder.Code)
	}

	if len(e.backend.changes()) != 0 {
		t.Fatal("an alert was changed from another address")
	}

	// Using the cookie from the wrong address ends the session.
	if recorder := e.do(session.get("/alerts/all")); recorder.Code != http.StatusSeeOther {
		t.Fatalf("the session survived a use from another address: status = %d", recorder.Code)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	session := e.loginAs("alice")

	if recorder := e.do(session.get("/logout")); recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /logout: status = %d", recorder.Code)
	}

	// Without the CSRF token the session survives.
	if recorder := e.do(newRequest("POST", "/logout", url.Values{}, withCookie(session.token))); recorder.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf: status = %d", recorder.Code)
	}

	if recorder := e.do(session.get("/")); !strings.Contains(recorder.Body.String(), "alice") {
		t.Fatal("a forged logout ended the session")
	}

	recorder := e.do(session.post("/logout", nil))
	if recorder.Code != http.StatusSeeOther || location(recorder) != "/" {
		t.Fatalf("logout: status = %d", recorder.Code)
	}

	cleared := strings.Join(recorder.Header().Values("Set-Cookie"), "|")
	if !strings.Contains(cleared, "Max-Age=0") || !strings.Contains(cleared, CookieName+"=;") {
		t.Fatalf("cookie not cleared: %q", cleared)
	}

	if recorder := e.do(session.get("/alerts/all")); recorder.Code != http.StatusSeeOther {
		t.Fatalf("the session still works after logout: status = %d", recorder.Code)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestNoSessionIsCreatedWithoutRandomBytes(t *testing.T) {
	backend := newFakeBackend()

	handler, err := NewHandler(backend, nil, Options{Random: failingReader{}})
	if err != nil {
		t.Fatal(err)
	}

	recorder := httpDo(handler, newRequest("POST", "/login", url.Values{"name": {"alice"}, "password": {testPassword}}))

	if recorder.Code != http.StatusServiceUnavailable || tokenFrom(recorder) != "" {
		t.Fatalf("status = %d, cookie = %q", recorder.Code, tokenFrom(recorder))
	}
}

func TestRevokingAUserEndsTheirSessions(t *testing.T) {
	e := newEnv(t)

	alice := e.loginAs("alice")
	bob := e.loginAs("bob", withIP("192.0.2.12"))

	if count := e.handler.Sessions().RevokeUser("alice"); count != 1 {
		t.Fatalf("revoked %d sessions", count)
	}

	if recorder := e.do(alice.get("/alerts/all")); recorder.Code != http.StatusSeeOther {
		t.Fatal("a revoked session still works")
	}

	if recorder := e.do(newRequest("GET", "/alerts/all", nil, withCookie(bob.token), withIP("192.0.2.12"))); recorder.Code != http.StatusOK {
		t.Fatalf("another user's session was ended: status = %d", recorder.Code)
	}

	e.handler.Sessions().RevokeAll()

	if recorder := e.do(newRequest("GET", "/alerts/all", nil, withCookie(bob.token), withIP("192.0.2.12"))); recorder.Code != http.StatusSeeOther {
		t.Fatal("RevokeAll left a session")
	}
}
