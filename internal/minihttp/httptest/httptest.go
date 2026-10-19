// Package httptest mirrors the small part of net/http/httptest that AAMM-NG's
// tests use, on top of internal/minihttp (plain HTTP only).
package httptest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"

	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

// ResponseRecorder records a handler's response.
type ResponseRecorder struct {
	Code      int
	HeaderMap http.Header
	Body      *bytes.Buffer
	Flushed   bool

	snapshot    http.Header
	wroteHeader bool
}

func NewRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		Code:      http.StatusOK,
		HeaderMap: make(http.Header),
		Body:      new(bytes.Buffer),
	}
}

func (r *ResponseRecorder) Header() http.Header {
	if r.HeaderMap == nil {
		r.HeaderMap = make(http.Header)
	}

	return r.HeaderMap
}

func (r *ResponseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}

	r.Code = code
	r.wroteHeader = true
	r.snapshot = cloneHeader(r.Header())
}

func (r *ResponseRecorder) Write(data []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	if r.Body != nil {
		r.Body.Write(data)
	}

	return len(data), nil
}

func (r *ResponseRecorder) WriteString(s string) (int, error) {
	return r.Write([]byte(s))
}

// Result returns the response as written, snapshotting headers at the first
// WriteHeader/Write like net/http/httptest.
func (r *ResponseRecorder) Result() *http.Response {
	if r.snapshot == nil {
		r.snapshot = cloneHeader(r.Header())
	}

	body := []byte(nil)
	if r.Body != nil {
		body = r.Body.Bytes()
	}

	return &http.Response{
		StatusCode:    r.Code,
		Status:        fmt.Sprintf("%03d %s", r.Code, http.StatusText(r.Code)),
		Header:        r.snapshot,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func cloneHeader(header http.Header) http.Header {
	clone := make(http.Header, len(header))

	for key, values := range header {
		clone[key] = append([]string(nil), values...)
	}

	return clone
}

// NewRequest builds a server-side request for tests.
func NewRequest(method, target string, body io.Reader) *http.Request {
	if method == "" {
		method = http.MethodGet
	}

	request, err := http.NewRequestWithContext(
		context.Background(),
		method,
		target,
		body,
	)
	if err != nil {
		panic("invalid NewRequest arguments; " + err.Error())
	}

	if request.URL.Scheme != "" && request.URL.Scheme != "http" {
		panic("httptest: only http targets are supported")
	}

	request.Host = request.URL.Host
	if request.Host == "" {
		request.Host = "example.com"
	}

	// Server-side requests carry an origin-form URL.
	request.URL = &url.URL{
		Path:     request.URL.Path,
		RawPath:  request.URL.RawPath,
		RawQuery: request.URL.RawQuery,
	}
	request.RemoteAddr = "192.0.2.1:1234"

	return request
}

// Server is a loopback test server.
type Server struct {
	URL      string
	Listener net.Listener

	server *http.Server
	done   chan struct{}
}

func NewServer(handler http.Handler) *Server {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("httptest: failed to listen: %v", err))
	}

	server := &Server{
		URL:      "http://" + listener.Addr().String(),
		Listener: listener,
		server:   &http.Server{Handler: handler},
		done:     make(chan struct{}),
	}

	go func() {
		defer close(server.done)
		_ = server.server.Serve(listener)
	}()

	return server
}

func (s *Server) Close() {
	_ = s.server.Close()
	<-s.done
}
