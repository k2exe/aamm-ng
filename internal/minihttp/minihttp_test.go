package minihttp_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	http "github.com/k2exe/aamm-ng/internal/minihttp"
	"github.com/k2exe/aamm-ng/internal/minihttp/httptest"
)

// rawExchange sends raw bytes to a server running handler and returns
// everything the server wrote before closing the connection.
func rawExchange(t *testing.T, handler http.Handler, raw string) string {
	t.Helper()

	server := httptest.NewServer(handler)
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}

	out, _ := io.ReadAll(conn)

	return string(out)
}

func echo(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, r.Method+" "+r.URL.Path+" host="+r.Host+" form="+r.PostForm.Get("a"))
}

func TestServerAnswersSimpleRequest(t *testing.T) {
	out := rawExchange(t, http.HandlerFunc(echo),
		"GET /x HTTP/1.1\r\nHost: node.local.mesh\r\n\r\n")

	if !strings.HasPrefix(out, "HTTP/1.1 200 OK\r\n") ||
		!strings.Contains(out, "Connection: close\r\n") ||
		!strings.Contains(out, "Content-Length: ") ||
		!strings.HasSuffix(out, "GET /x host=node.local.mesh form=") {
		t.Fatalf("unexpected response: %q", out)
	}
}

func TestServerParsesFormBody(t *testing.T) {
	out := rawExchange(t, http.HandlerFunc(echo),
		"POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 5\r\n\r\na=b+c")
	if !strings.HasSuffix(out, "form=b c") {
		t.Fatalf("unexpected response: %q", out)
	}
}

func TestServerRejectsMalformedRequests(t *testing.T) {
	cases := map[string]struct {
		raw    string
		status string
	}{
		"bare LF request line":      {"GET / HTTP/1.1\nHost: h\n\n", "400"},
		"bare LF header":            {"GET / HTTP/1.1\r\nHost: h\n\r\n", "400"},
		"missing host on 1.1":       {"GET / HTTP/1.1\r\n\r\n", "400"},
		"duplicate host":            {"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "400"},
		"bad host chars":            {"GET / HTTP/1.1\r\nHost: a b\r\n\r\n", "400"},
		"transfer-encoding":         {"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "501"},
		"TE plus CL (smuggling)":    {"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", "501"},
		"duplicate content-length":  {"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", "400"},
		"signed content-length":     {"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +1\r\n\r\nx", "400"},
		"huge content-length":       {"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999\r\n\r\n", "413"},
		"obs-fold":                  {"GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n  continued\r\n\r\n", "400"},
		"space before colon":        {"GET / HTTP/1.1\r\nHost: h\r\nX-A : 1\r\n\r\n", "400"},
		"absolute-form target":      {"GET http://evil/ HTTP/1.1\r\nHost: h\r\n\r\n", "400"},
		"authority-form (CONNECT)":  {"CONNECT h:443 HTTP/1.1\r\nHost: h\r\n\r\n", "400"},
		"http/2 preface":            {"PRI * HTTP/2.0\r\n\r\n", "505"},
		"extra request-line fields": {"GET / HTTP/1.1 x\r\nHost: h\r\n\r\n", "400"},
		"control char in target":    {"GET /a\x01b HTTP/1.1\r\nHost: h\r\n\r\n", "400"},
		"NUL in header":             {"GET / HTTP/1.1\r\nHost: h\r\nX: a\x00b\r\n\r\n", "400"},
		"oversize header":           {"GET / HTTP/1.1\r\nHost: h\r\nX: " + strings.Repeat("a", 20000) + "\r\n\r\n", "431"},
		"oversize request line":     {"GET /" + strings.Repeat("a", 9000) + " HTTP/1.1\r\nHost: h\r\n\r\n", "414"},
		"invalid method":            {"G@T / HTTP/1.1\r\nHost: h\r\n\r\n", "400"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := rawExchange(t, http.HandlerFunc(echo), tc.raw)

			if !strings.HasPrefix(out, "HTTP/1.1 "+tc.status+" ") {
				t.Fatalf("response = %q; want status %s", firstLine(out), tc.status)
			}
		})
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\r\n")
	return line
}

func TestServerEnforcesHeaderTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{
		Handler:           http.HandlerFunc(echo),
		ReadHeaderTimeout: 200 * time.Millisecond,
	}

	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: h\r\n") // never finished

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	start := time.Now()
	_, _ = io.ReadAll(conn)

	if time.Since(start) > time.Second {
		t.Fatalf("slow header connection survived %v", time.Since(start))
	}
}

func TestResponseHeaderInjectionIsNeutralised(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "a\r\nInjected: yes")
		w.Header().Set("Bad Name", "v")
		_, _ = io.WriteString(w, "ok")
	})

	out := rawExchange(t, handler, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	if strings.Contains(out, "\r\nInjected:") || strings.Contains(out, "Bad Name") {
		t.Fatalf("header injection not neutralised: %q", out)
	}
}

func TestHeadAndNoContentHaveNoBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		_, _ = io.WriteString(w, "body")
	})

	out := rawExchange(t, handler, "HEAD / HTTP/1.1\r\nHost: h\r\n\r\n")
	if !strings.Contains(out, "Content-Length: 4\r\n") || strings.HasSuffix(out, "body") {
		t.Fatalf("HEAD response wrong: %q", out)
	}

	out = rawExchange(t, handler, "GET /204 HTTP/1.1\r\nHost: h\r\n\r\n")
	if strings.Contains(out, "Content-Length") {
		t.Fatalf("204 must not carry Content-Length: %q", out)
	}
}

func TestHandlerPanicYields500(t *testing.T) {
	out := rawExchange(t,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
		"GET / HTTP/1.1\r\nHost: h\r\n\r\n")

	if !strings.HasPrefix(out, "HTTP/1.1 500 ") {
		t.Fatalf("response = %q; want 500", firstLine(out))
	}
}

func TestClientRoundTripAndNoRedirectFollowing(t *testing.T) {
	var gotCookie, gotHost, gotBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotHost = r.Host
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)

		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusSeeOther)
			return
		}

		_, _ = io.WriteString(w, "hello")
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		server.URL+"/x?q=1", strings.NewReader("a=b"))
	if err != nil {
		t.Fatal(err)
	}

	request.Host = "node.local.mesh"
	request.Header.Set("Cookie", "authV1=abc")

	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	data, _ := io.ReadAll(response.Body)
	response.Body.Close()

	if string(data) != "hello" || gotCookie != "authV1=abc" ||
		gotHost != "node.local.mesh" || gotBody != "a=b" {
		t.Fatalf("round trip mismatch: %q %q %q %q", data, gotCookie, gotHost, gotBody)
	}

	response, err = client.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	if response.StatusCode != http.StatusSeeOther ||
		response.Header.Get("Location") != "/elsewhere" {
		t.Fatalf("redirect was followed or lost: %d %v", response.StatusCode, response.Header)
	}
}

func TestClientRejectsUnsafeInput(t *testing.T) {
	client := &http.Client{Timeout: time.Second}

	newReq := func(target string) *http.Request {
		r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}

		return r
	}

	if _, err := client.Do(newReq("https://127.0.0.1/")); err == nil {
		t.Fatal("https URL accepted; TLS is intentionally unsupported")
	}

	bad := newReq("http://127.0.0.1:1/")
	bad.Host = "evil\r\nX: y"

	if _, err := client.Do(bad); err == nil {
		t.Fatal("Host with CRLF accepted")
	}

	bad = newReq("http://127.0.0.1:1/")
	bad.Header.Set("Cookie", "a=b\r\nX-Injected: 1")

	if _, err := client.Do(bad); err == nil {
		t.Fatal("header value with CRLF accepted")
	}
}

func TestClientDecodesChunkedAndEOFBodies(t *testing.T) {
	serve := func(raw string) string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			_, _ = bufio.NewReader(conn).ReadString('\n')
			_, _ = io.WriteString(conn, raw)
		}()

		response, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + listener.Addr().String() + "/")
		if err != nil {
			return "ERR:" + err.Error()
		}
		defer response.Body.Close()

		data, err := io.ReadAll(response.Body)
		if err != nil {
			return "READERR:" + err.Error()
		}

		return string(data)
	}

	if got := serve("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX: t\r\n\r\n"); got != "hello world" {
		t.Fatalf("chunked = %q", got)
	}

	if got := serve("HTTP/1.0 200 OK\r\n\r\nuntil-eof"); got != "until-eof" {
		t.Fatalf("eof body = %q", got)
	}

	if got := serve("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"); !strings.HasPrefix(got, "READERR:") {
		t.Fatalf("truncated body not detected: %q", got)
	}

	if got := serve("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"); !strings.HasPrefix(got, "READERR:") {
		t.Fatalf("bad chunk size accepted: %q", got)
	}

	if got := serve("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); got != "ok" {
		t.Fatalf("interim response not skipped: %q", got)
	}
}

func TestClientTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			conn.Close()
		}
	}()

	start := time.Now()

	_, err = (&http.Client{Timeout: 200 * time.Millisecond}).Get("http://" + listener.Addr().String() + "/")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout not enforced: err=%v after %v", err, time.Since(start))
	}
}

func TestMuxRoutingAndPathValues(t *testing.T) {
	mux := http.NewServeMux()

	record := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, name+":"+r.PathValue("target"))
		}
	}

	mux.HandleFunc("/", record("root"))
	mux.HandleFunc("/alerts/", record("alerts"))
	mux.HandleFunc("/alerts/new", record("new"))
	mux.HandleFunc("/alerts/{target}/delete", record("delete"))

	cases := map[string]string{
		"/":                       "root:",
		"/nope":                   "root:",
		"/alerts/wx":              "alerts:",
		"/alerts/new":             "new:",
		"/alerts/wx/delete":       "delete:wx",
		"/alerts/a%2Fb/delete":    "delete:a/b",
		"/alerts/wx/delete/extra": "alerts:",
	}

	for path, want := range cases {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

		if got := recorder.Body.String(); got != want {
			t.Errorf("%s -> %q; want %q", path, got, want)
		}
	}

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/alerts/../x", nil))

	if recorder.Code != http.StatusMovedPermanently || recorder.Header().Get("Location") != "/x" {
		t.Errorf("unclean path: %d %q", recorder.Code, recorder.Header().Get("Location"))
	}

	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/alerts", nil))

	if recorder.Code != http.StatusMovedPermanently || recorder.Header().Get("Location") != "/alerts/" {
		t.Errorf("subtree redirect: %d %q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestCookieAndForm(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/p?x=1", strings.NewReader("a=1&a=2&b=%20"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	request.AddCookie(&http.Cookie{Name: "authV1", Value: "tok"})
	request.AddCookie(&http.Cookie{Name: "other", Value: "v"})

	cookie, err := request.Cookie("authV1")
	if err != nil || cookie.Value != "tok" {
		t.Fatalf("cookie = %v, %v", cookie, err)
	}

	if _, err := request.Cookie("missing"); err == nil {
		t.Fatal("missing cookie reported present")
	}

	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}

	if got := request.PostForm["a"]; len(got) != 2 || request.PostForm.Get("b") != " " {
		t.Fatalf("PostForm = %v", request.PostForm)
	}

	if request.Form.Get("x") != "1" || request.PostForm.Get("x") != "" {
		t.Fatalf("Form = %v PostForm = %v", request.Form, request.PostForm)
	}
}

func TestMaxBytesReader(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/p", strings.NewReader("a=aaaaaaaaaaaaaaaa"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Body = http.MaxBytesReader(httptest.NewRecorder(), request.Body, 4)

	if err := request.ParseForm(); err == nil {
		t.Fatal("ParseForm accepted a body over the MaxBytesReader limit")
	}
}

func TestErrorAndRedirectHelpers(t *testing.T) {
	recorder := httptest.NewRecorder()
	http.Error(recorder, "nope", http.StatusForbidden)

	if recorder.Code != 403 ||
		recorder.Header().Get("X-Content-Type-Options") != "nosniff" ||
		recorder.Body.String() != "nope\n" {
		t.Fatalf("Error: %d %v %q", recorder.Code, recorder.Header(), recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	http.Redirect(recorder, httptest.NewRequest(http.MethodPost, "/a/b", nil), "/alerts/x", http.StatusSeeOther)

	if recorder.Code != 303 || recorder.Header().Get("Location") != "/alerts/x" {
		t.Fatalf("Redirect: %d %v", recorder.Code, recorder.Header())
	}
}

func TestShutdownWaitsForHandlersAndStopsAccepting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	entered := make(chan struct{})

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered)
			<-release
			_, _ = io.WriteString(w, "done")
		}),
	}

	serveDone := make(chan error, 1)

	go func() { serveDone <- server.Serve(listener) }()

	result := make(chan string, 1)

	go func() {
		response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + listener.Addr().String() + "/")
		if err != nil {
			result <- "ERR:" + err.Error()
			return
		}
		defer response.Body.Close()

		data, _ := io.ReadAll(response.Body)
		result <- string(data)
	}()

	<-entered

	shutdownDone := make(chan error, 1)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		shutdownDone <- server.Shutdown(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	close(release)

	if got := <-result; got != "done" {
		t.Fatalf("in-flight request result = %q", got)
	}

	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}

	if err := <-serveDone; err != http.ErrServerClosed {
		t.Fatalf("Serve = %v; want ErrServerClosed", err)
	}
}
