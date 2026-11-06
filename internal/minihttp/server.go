package minihttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxHeaderBytes = 16 << 10
	maxRequestBodyBytes   = 10 << 20
	maxResponseBodyBytes  = 8 << 20
	maxConnections        = 64
)

// Server serves plain HTTP/1.x. Each connection handles exactly one request
// and is then closed (Connection: close), so there is no keep-alive state.
type Server struct {
	Handler           Handler
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	MaxHeaderBytes    int

	mu       sync.Mutex
	closed   bool
	listener net.Listener
	conns    map[net.Conn]*atomic.Bool // value: handler started
	wg       sync.WaitGroup
}

func (s *Server) Serve(listener net.Listener) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		_ = listener.Close()

		return ErrServerClosed
	}

	s.listener = listener
	if s.conns == nil {
		s.conns = make(map[net.Conn]*atomic.Bool)
	}

	s.mu.Unlock()

	slots := make(chan struct{}, maxConnections)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			return err
		}

		select {
		case slots <- struct{}{}:
		default:
			rejectBusy(conn)
			continue
		}

		started := new(atomic.Bool)

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-slots
			_ = conn.Close()

			return ErrServerClosed
		}

		s.conns[conn] = started
		s.wg.Add(1)
		s.mu.Unlock()

		go func() {
			defer func() {
				<-slots

				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()

				s.wg.Done()
			}()

			s.serveConn(conn, started)
		}()
	}
}

func rejectBusy(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(
		conn,
		"HTTP/1.1 503 Service Unavailable\r\n"+
			"Content-Length: 0\r\nConnection: close\r\n\r\n",
	)
	_ = conn.Close()
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.closed
}

// Shutdown stops accepting, abandons connections that have not yet delivered
// a request, and waits for running handlers until ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true

	if s.listener != nil {
		_ = s.listener.Close()
	}

	for conn, started := range s.conns {
		if !started.Load() {
			_ = conn.Close()
		}
	}
	s.mu.Unlock()

	done := make(chan struct{})

	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops accepting and closes every connection immediately.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true

	if s.listener != nil {
		_ = s.listener.Close()
	}

	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()

	return nil
}

func (s *Server) serveConn(conn net.Conn, started *atomic.Bool) {
	defer conn.Close()

	headerTimeout := s.ReadHeaderTimeout
	if headerTimeout <= 0 {
		headerTimeout = 10 * time.Second
	}

	maxHeader := s.MaxHeaderBytes
	if maxHeader <= 0 {
		maxHeader = defaultMaxHeaderBytes
	}

	_ = conn.SetReadDeadline(time.Now().Add(headerTimeout))

	reader := bufio.NewReaderSize(conn, 4096)

	request, err := readRequest(reader, maxHeader)
	if err != nil {
		var parseErr *parseError
		if errors.As(err, &parseErr) {
			writeSimple(conn, parseErr.status, parseErr.msg)
		}

		return
	}

	started.Store(true)

	now := time.Now()

	if s.ReadTimeout > 0 {
		_ = conn.SetReadDeadline(now.Add(s.ReadTimeout))
	} else {
		_ = conn.SetReadDeadline(time.Time{})
	}

	if s.WriteTimeout > 0 {
		_ = conn.SetWriteDeadline(now.Add(s.WriteTimeout))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	request.ctx = ctx
	request.RemoteAddr = conn.RemoteAddr().String()

	writer := &responseWriter{header: make(Header), head: request.Method == MethodHead}

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				fmt.Fprintf(os.Stderr, "aamm-ng-web: handler panic: %v\n", recovered)

				if !writer.wroteHeader {
					writer.header = make(Header)
					writer.body.Reset()
					writer.WriteHeader(StatusInternalServerError)
				}
			}
		}()

		handler := s.Handler
		if handler == nil {
			handler = HandlerFunc(NotFound)
		}

		handler.ServeHTTP(writer, request)
	}()

	writer.finish(conn)
}

// readRequest parses one request. HTTP/1.1 requests must carry Host, targets
// must be origin-form, and any Transfer-Encoding is refused.
func readRequest(br *bufio.Reader, maxHeader int) (*Request, error) {
	line, err := readLine(br, 8192)
	if err != nil {
		var parseErr *parseError
		if errors.As(err, &parseErr) && parseErr.status == StatusHeaderFieldsTooLarg {
			return nil, &parseError{
				status: StatusRequestURITooLong,
				msg:    "request line too long",
			}
		}

		return nil, err
	}

	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return nil, badRequest("malformed request line")
	}

	method, target, version := parts[0], parts[1], parts[2]

	if !isToken(method) {
		return nil, badRequest("invalid method")
	}

	minor, ok := parseVersion(version)
	if !ok {
		return nil, &parseError{
			status: StatusVersionNotSupported,
			msg:    "unsupported HTTP version",
		}
	}

	if !strings.HasPrefix(target, "/") {
		return nil, badRequest("unsupported request target")
	}

	for i := 0; i < len(target); i++ {
		if target[i] <= ' ' || target[i] == 0x7f {
			return nil, badRequest("invalid request target")
		}
	}

	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, badRequest("invalid request target")
	}

	header, err := readHeader(br, maxHeader)
	if err != nil {
		return nil, err
	}

	if len(header.Values("Transfer-Encoding")) > 0 {
		return nil, &parseError{
			status: StatusNotImplemented,
			msg:    "Transfer-Encoding is not supported",
		}
	}

	hosts := header.Values("Host")
	if len(hosts) > 1 {
		return nil, badRequest("multiple Host headers")
	}

	host := ""
	if len(hosts) == 1 {
		host = hosts[0]
		if host != "" && !validHost(host) {
			return nil, badRequest("invalid Host header")
		}
	}

	if minor == 1 && host == "" {
		return nil, badRequest("missing Host header")
	}

	length, err := parseContentLength(header)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Method: method,
		URL:    parsed,
		Header: header,
		Host:   host,
	}

	switch {
	case length > maxRequestBodyBytes:
		return nil, &parseError{
			status: StatusRequestEntityTooBig,
			msg:    "request body too large",
		}

	case length > 0:
		request.ContentLength = length
		request.Body = io.NopCloser(&bodyReader{reader: br, left: length})

	default:
		request.Body = NoBody
	}

	// Host lives in Request.Host, as with net/http.
	header.Del("Host")

	return request, nil
}

func writeSimple(conn net.Conn, status int, msg string) {
	body := msg + "\n"

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintf(
		conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\n"+
			"X-Content-Type-Options: nosniff\r\nContent-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s",
		status,
		StatusText(status),
		len(body),
		body,
	)
}

type responseWriter struct {
	header      Header
	status      int
	wroteHeader bool
	head        bool
	body        bytes.Buffer
}

func (w *responseWriter) Header() Header { return w.header }

func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}

	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %d", code))
	}

	w.wroteHeader = true
	w.status = code
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(StatusOK)
	}

	if !bodyAllowed(w.status) {
		return 0, errors.New("http: request method or response status code does not allow body")
	}

	if w.body.Len()+len(data) > maxResponseBodyBytes {
		return 0, errBodyTooLarge
	}

	return w.body.Write(data)
}

func bodyAllowed(status int) bool {
	return !(status >= 100 && status < 200) && status != 204 && status != 304
}

// finish sends the buffered response with an exact Content-Length.
func (w *responseWriter) finish(conn net.Conn) {
	if !w.wroteHeader {
		w.WriteHeader(StatusOK)
	}

	var out bytes.Buffer

	reason := StatusText(w.status)
	if reason == "" {
		reason = "Status"
	}

	fmt.Fprintf(&out, "HTTP/1.1 %d %s\r\n", w.status, reason)

	_ = writeHeader(
		&out,
		w.header,
		"Content-Length",
		"Transfer-Encoding",
		"Connection",
	)

	if bodyAllowed(w.status) {
		fmt.Fprintf(&out, "Content-Length: %d\r\n", w.body.Len())
	}

	out.WriteString("Connection: close\r\n\r\n")

	if bodyAllowed(w.status) && !w.head {
		out.Write(w.body.Bytes())
	}

	_, _ = conn.Write(out.Bytes())
}
