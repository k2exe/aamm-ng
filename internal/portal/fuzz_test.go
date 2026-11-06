package portal

import (
	"net/url"
	"strings"
	"testing"

	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

func fuzzRequest(method, path, body, cookie, origin, contentType string) (request *http.Request) {
	defer func() {
		if recover() != nil {
			request = nil
		}
	}()

	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \r\n\x00") {
		return nil
	}

	if _, err := url.ParseRequestURI(path); err != nil {
		return nil
	}

	request = newRequest(method, path, nil)

	request.Body = http.NoBody
	if body != "" {
		request.Body = nopCloser{strings.NewReader(body)}
	}

	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	if origin != "" {
		request.Header.Set("Origin", origin)
	}

	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}

	return request
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

var fuzzSeeds = [][6]string{
	{"GET", "/", "", "", "", ""},
	{"POST", "/login", "name=alice&password=x", "", "http://portal.test", "application/x-www-form-urlencoded"},
	{"POST", "/alerts/new", "csrf=x&target=all&message=hi", "", "http://portal.test", "application/x-www-form-urlencoded"},
	{"POST", "/alerts/all/delete", "confirm=all", "aamm_portal=" + strings.Repeat("a", 64), "http://portal.test", "application/x-www-form-urlencoded"},
	{"GET", "/alerts/%2e%2e/x", "", "", "", ""},
	{"PUT", "/settings", "{}", "", "", "application/json"},
}

// Without a session no input may change an alert or reach the daemon beyond
// a login check, and no input may produce a server error.
func FuzzUnauthenticatedRequests(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4], seed[5])
	}

	f.Fuzz(func(t *testing.T, method, path, body, cookie, origin, contentType string) {
		e := newEnv(t)

		request := fuzzRequest(method, path, body, cookie, origin, contentType)
		if request == nil {
			return
		}

		recorder := e.do(request)

		if recorder.Code >= 500 && recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d for %s %q", recorder.Code, method, path)
		}

		if recorder.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("a response has no Content-Security-Policy")
		}

		if len(e.backend.changes()) != 0 {
			t.Fatalf("an alert was changed without a session: %+v", e.backend.changes())
		}

		for _, entry := range e.backend.calls {
			if entry.op != "login" {
				t.Fatalf("the daemon was called without a session: %+v", entry)
			}
		}
	})
}

// A viewer can never change an alert, whatever the request, even with a
// valid session, CSRF token and origin.
func FuzzViewerNeverChangesAlerts(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed[0], seed[1], seed[2])
	}

	f.Add("POST", "/alerts/all", "message=x")
	f.Add("POST", "/alerts/all/delete", "confirm=all")
	f.Add("POST", "/alerts/new", "target=a&message=b")

	f.Fuzz(func(t *testing.T, method, path, body string) {
		e := newEnv(t)
		viewer := e.loginAs("bob")

		request := fuzzRequest(method, path, body, CookieName+"="+viewer.token, "http://"+testHost,
			"application/x-www-form-urlencoded")
		if request == nil {
			return
		}

		// A valid CSRF token is added to every body.
		if body != "" {
			request.Body = nopCloser{strings.NewReader("csrf=" + viewer.csrf + "&" + body)}
		} else {
			request.Body = nopCloser{strings.NewReader("csrf=" + viewer.csrf)}
		}

		recorder := e.do(request)

		if recorder.Code >= 500 && recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d for %s %q", recorder.Code, method, path)
		}

		if changes := e.backend.changes(); len(changes) != 0 {
			t.Fatalf("a viewer changed an alert with %s %q %q: %+v", method, path, body, changes)
		}
	})
}
