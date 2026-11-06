// Package minihttp is a deliberately small, plain-HTTP/1.1 subset with the
// same names and semantics as the parts of net/http that AAMM-NG uses.
//
// It exists because importing net/http links crypto/tls and crypto/x509 into
// the binary even when TLS is never used. AAMM-NG only speaks plain HTTP over
// loopback (the AREDN web server terminates the browser connection and
// forwards through the CGI bridge), so this package intentionally has no TLS,
// no HTTP/2, no keep-alive, no chunked request bodies, no proxy support and no
// redirect following. Every connection carries exactly one request.
package minihttp

import (
	"errors"
	"io"
	"net/textproto"
	"strings"
)

const (
	MethodGet  = "GET"
	MethodHead = "HEAD"
	MethodPost = "POST"
	MethodPut  = "PUT"
)

const (
	StatusOK                  = 200
	StatusNoContent           = 204
	StatusMovedPermanently    = 301
	StatusFound               = 302
	StatusSeeOther            = 303
	StatusNotModified         = 304
	StatusBadRequest          = 400
	StatusUnauthorized        = 401
	StatusForbidden           = 403
	StatusNotFound            = 404
	StatusMethodNotAllowed    = 405
	StatusConflict            = 409
	StatusLengthRequired      = 411
	StatusRequestEntityTooBig = 413
	StatusRequestURITooLong   = 414
	StatusHeaderFieldsTooLarg = 431
	StatusInternalServerError = 500
	StatusNotImplemented      = 501
	StatusServiceUnavailable  = 503
	StatusVersionNotSupported = 505
)

var statusText = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	200: "OK",
	201: "Created",
	202: "Accepted",
	204: "No Content",
	206: "Partial Content",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	408: "Request Timeout",
	409: "Conflict",
	411: "Length Required",
	413: "Request Entity Too Large",
	414: "Request URI Too Long",
	415: "Unsupported Media Type",
	422: "Unprocessable Entity",
	429: "Too Many Requests",
	431: "Request Header Fields Too Large",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
	505: "HTTP Version Not Supported",
}

// StatusText returns the reason phrase for code, or "" if it is unknown.
func StatusText(code int) string {
	return statusText[code]
}

var (
	// ErrServerClosed is returned by Server.Serve after Shutdown or Close.
	ErrServerClosed = errors.New("http: Server closed")

	errBodyTooLarge = errors.New("http: response body too large")
)

// Header is a case-insensitive multi-map of header fields.
type Header map[string][]string

func CanonicalHeaderKey(s string) string {
	return textproto.CanonicalMIMEHeaderKey(s)
}

func (h Header) Add(key, value string) {
	key = CanonicalHeaderKey(key)
	h[key] = append(h[key], value)
}

func (h Header) Set(key, value string) {
	h[CanonicalHeaderKey(key)] = []string{value}
}

func (h Header) Get(key string) string {
	values := h[CanonicalHeaderKey(key)]
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

func (h Header) Values(key string) []string {
	return h[CanonicalHeaderKey(key)]
}

// Clone returns a deep copy of h.
func (h Header) Clone() Header {
	if h == nil {
		return nil
	}

	clone := make(Header, len(h))

	for key, values := range h {
		clone[key] = append([]string(nil), values...)
	}

	return clone
}

func (h Header) Del(key string) {
	delete(h, CanonicalHeaderKey(key))
}

// Handler responds to a request.
type Handler interface {
	ServeHTTP(ResponseWriter, *Request)
}

type HandlerFunc func(ResponseWriter, *Request)

func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}

// ResponseWriter assembles a response. Bodies are buffered in memory and sent
// with an exact Content-Length when the handler returns.
type ResponseWriter interface {
	Header() Header
	Write([]byte) (int, error)
	WriteHeader(statusCode int)
}

type noBody struct{}

func (noBody) Read([]byte) (int, error)         { return 0, io.EOF }
func (noBody) Close() error                     { return nil }
func (noBody) WriteTo(io.Writer) (int64, error) { return 0, nil }

// NoBody is an empty request/response body.
var NoBody = noBody{}

// isToken reports whether s is a non-empty RFC 9110 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		if !isTokenByte(s[i]) {
			return false
		}
	}

	return true
}

func isTokenByte(c byte) bool {
	switch {
	case c >= '0' && c <= '9',
		c >= 'a' && c <= 'z',
		c >= 'A' && c <= 'Z':
		return true
	}

	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// validFieldValue rejects control characters other than horizontal tab, which
// blocks header injection through CR, LF and NUL.
func validFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}

	return true
}

// validHost accepts the characters that can appear in a Host header value
// (reg-name, IPv4, bracketed IPv6, optional port).
func validHost(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z':
		case strings.IndexByte("-._~%:[]", c) >= 0:
		default:
			return false
		}
	}

	return true
}
