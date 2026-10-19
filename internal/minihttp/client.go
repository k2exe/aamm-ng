package minihttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxResponseHeaderBytes = 64 << 10
	maxUnknownLengthBody   = 1 << 20
)

// Response is a response received by a Client.
type Response struct {
	Status        string
	StatusCode    int
	Header        Header
	Body          io.ReadCloser
	ContentLength int64
	Request       *Request
}

// Client performs plain-HTTP requests. It never follows redirects, never
// reuses connections and never consults proxy environment variables; the
// 3xx response is returned to the caller unchanged.
type Client struct {
	// Timeout bounds the whole exchange, including reading the body.
	Timeout time.Duration
}

func (c *Client) Get(target string) (*Response, error) {
	request, err := NewRequestWithContext(
		context.Background(),
		MethodGet,
		target,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return c.Do(request)
}

func (c *Client) Do(request *Request) (*Response, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("http: nil Request.URL")
	}

	if request.URL.Scheme != "http" {
		return nil, fmt.Errorf(
			"http: unsupported protocol scheme %q (plain http only)",
			request.URL.Scheme,
		)
	}

	address := request.URL.Host
	if address == "" {
		return nil, errors.New("http: no Host in request URL")
	}

	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(strings.Trim(address, "[]"), "80")
	}

	host := request.Host
	if host == "" {
		host = request.URL.Host
	}

	if !validHost(host) {
		return nil, errors.New("http: invalid Host header")
	}

	if !isToken(request.Method) {
		return nil, errors.New("http: invalid method")
	}

	for name, values := range request.Header {
		if !isToken(name) {
			return nil, fmt.Errorf("http: invalid header field name %q", name)
		}

		for _, value := range values {
			if !validFieldValue(value) {
				return nil, fmt.Errorf("http: invalid header field value for %q", name)
			}
		}
	}

	body, length, err := outgoingBody(request)
	if err != nil {
		return nil, err
	}

	ctx := request.Context()

	dialer := net.Dialer{Timeout: c.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	if c.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })

	var closeOnce sync.Once

	closeAll := func() {
		closeOnce.Do(func() {
			stop()
			_ = conn.Close()
		})
	}

	response, err := roundTrip(conn, request, host, body, length)
	if err != nil {
		closeAll()

		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		return nil, err
	}

	response.Body = &connBody{reader: response.Body, closeFn: closeAll}
	response.Request = request

	return response, nil
}

// outgoingBody returns the bytes to send. A body is only sent when the
// caller declared its length (the CGI bridge always does); an undeclared
// length is buffered with a hard cap rather than sent chunked.
func outgoingBody(request *Request) ([]byte, int64, error) {
	if request.Body == nil || request.Body == NoBody {
		return nil, 0, nil
	}

	defer request.Body.Close()

	switch {
	case request.ContentLength > 0:
		data := make([]byte, request.ContentLength)

		if _, err := io.ReadFull(request.Body, data); err != nil {
			return nil, 0, fmt.Errorf("http: read request body: %w", err)
		}

		return data, request.ContentLength, nil

	case request.ContentLength < 0:
		data, err := io.ReadAll(io.LimitReader(request.Body, maxUnknownLengthBody+1))
		if err != nil {
			return nil, 0, fmt.Errorf("http: read request body: %w", err)
		}

		if len(data) > maxUnknownLengthBody {
			return nil, 0, errors.New("http: request body too large")
		}

		return data, int64(len(data)), nil
	}

	return nil, 0, nil
}

func roundTrip(
	conn net.Conn,
	request *Request,
	host string,
	body []byte,
	length int64,
) (*Response, error) {
	var out bytes.Buffer

	fmt.Fprintf(&out, "%s %s HTTP/1.1\r\nHost: %s\r\n", request.Method, request.URL.RequestURI(), host)

	if err := writeHeader(&out, request.Header, "Host", "Content-Length", "Transfer-Encoding", "Connection"); err != nil {
		return nil, err
	}

	if length > 0 || request.Method == MethodPost || request.Method == MethodPut {
		fmt.Fprintf(&out, "Content-Length: %d\r\n", length)
	}

	out.WriteString("Connection: close\r\n\r\n")
	out.Write(body)

	if _, err := conn.Write(out.Bytes()); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)

	for {
		response, err := readResponse(br, request.Method)
		if err != nil {
			return nil, err
		}

		// Skip interim 1xx responses.
		if response.StatusCode >= 100 && response.StatusCode < 200 {
			continue
		}

		return response, nil
	}
}

func readResponse(br *bufio.Reader, method string) (*Response, error) {
	line, err := readLine(br, 8192)
	if err != nil {
		return nil, noEOF(err)
	}

	version, rest, found := strings.Cut(line, " ")
	if !found {
		return nil, errors.New("http: malformed status line")
	}

	if _, ok := parseVersion(version); !ok {
		return nil, errors.New("http: unsupported response version")
	}

	codeText, reason, _ := strings.Cut(rest, " ")
	if len(codeText) != 3 {
		return nil, errors.New("http: malformed status code")
	}

	code, err := strconv.Atoi(codeText)
	if err != nil || code < 100 {
		return nil, errors.New("http: malformed status code")
	}

	header, err := readHeader(br, maxResponseHeaderBytes)
	if err != nil {
		return nil, noEOF(err)
	}

	response := &Response{
		Status:     codeText + " " + reason,
		StatusCode: code,
		Header:     header,
	}

	switch {
	case method == MethodHead,
		code >= 100 && code < 200,
		code == 204,
		code == 304:
		response.Body = NoBody
		response.ContentLength = -1

	case strings.EqualFold(strings.TrimSpace(header.Get("Transfer-Encoding")), "chunked"):
		response.Body = io.NopCloser(newChunkedReader(br))
		response.ContentLength = -1

	default:
		length, err := parseContentLength(header)
		if err != nil {
			return nil, err
		}

		response.ContentLength = length

		if length >= 0 {
			response.Body = io.NopCloser(&bodyReader{reader: br, left: length})
		} else {
			response.Body = io.NopCloser(br) // read until the server closes
		}
	}

	return response, nil
}

type connBody struct {
	reader  io.Reader
	closeFn func()
}

func (b *connBody) Read(p []byte) (int, error) { return b.reader.Read(p) }

func (b *connBody) Close() error {
	b.closeFn()
	return nil
}

// ErrUseLastResponse is kept for source compatibility with net/http. Client
// never follows redirects, so nothing returns it.
var ErrUseLastResponse = errors.New("net/http: use last response")
