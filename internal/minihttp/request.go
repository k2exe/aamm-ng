package minihttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const maxFormSize = 10 << 20

// Request is an HTTP request, either received by a Server or built for a
// Client. Only plain HTTP exists in this package, so there is no TLS state.
type Request struct {
	Method        string
	URL           *url.URL
	Header        Header
	Body          io.ReadCloser
	ContentLength int64
	Host          string
	RemoteAddr    string
	Form          url.Values
	PostForm      url.Values

	pathValues map[string]string
	ctx        context.Context
}

// Cookie is a name/value pair carried in a request Cookie header.
type Cookie struct {
	Name  string
	Value string
}

func NewRequestWithContext(
	ctx context.Context,
	method string,
	target string,
	body io.Reader,
) (*Request, error) {
	if ctx == nil {
		return nil, errors.New("http: nil Context")
	}

	if method == "" {
		method = MethodGet
	}

	if !isToken(method) {
		return nil, fmt.Errorf("http: invalid method %q", method)
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Method: method,
		URL:    parsed,
		Header: make(Header),
		Host:   parsed.Host,
		ctx:    ctx,
	}

	setBody(request, body)

	return request, nil
}

func setBody(request *Request, body io.Reader) {
	if body == nil || body == NoBody {
		request.Body = NoBody
		return
	}

	if closer, ok := body.(io.ReadCloser); ok {
		request.Body = closer
	} else {
		request.Body = io.NopCloser(body)
	}

	switch typed := body.(type) {
	case *bytes.Buffer:
		request.ContentLength = int64(typed.Len())
	case *bytes.Reader:
		request.ContentLength = int64(typed.Len())
	case *strings.Reader:
		request.ContentLength = int64(typed.Len())
	}
}

// Context returns the request context, or context.Background() if unset.
func (r *Request) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}

	return context.Background()
}

// WithContext returns a shallow copy of r with its context changed.
func (r *Request) WithContext(ctx context.Context) *Request {
	if ctx == nil {
		panic("nil context")
	}

	clone := new(Request)
	*clone = *r
	clone.ctx = ctx

	return clone
}

// PathValue returns the value of a {name} wildcard matched by ServeMux.
func (r *Request) PathValue(name string) string {
	return r.pathValues[name]
}

// Cookie returns the named cookie from the Cookie header.
func (r *Request) Cookie(name string) (*Cookie, error) {
	for _, line := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)

			key, value, found := strings.Cut(part, "=")
			if !found || key != name {
				continue
			}

			if len(value) > 1 &&
				value[0] == '"' &&
				value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}

			return &Cookie{Name: key, Value: value}, nil
		}
	}

	return nil, errors.New("http: named cookie not present")
}

// AddCookie appends a cookie to the request Cookie header.
func (r *Request) AddCookie(cookie *Cookie) {
	pair := cookie.Name + "=" + cookie.Value

	if existing := r.Header.Get("Cookie"); existing != "" {
		r.Header.Set("Cookie", existing+"; "+pair)
		return
	}

	r.Header.Set("Cookie", pair)
}

// ParseForm populates r.Form and r.PostForm from the URL query and, for
// POST/PUT bodies with an urlencoded Content-Type, the request body.
func (r *Request) ParseForm() error {
	var err error

	if r.PostForm == nil {
		if r.Method == MethodPost || r.Method == MethodPut {
			r.PostForm, err = parsePostForm(r)
		}

		if r.PostForm == nil {
			r.PostForm = make(url.Values)
		}
	}

	if r.Form == nil {
		r.Form = make(url.Values, len(r.PostForm))

		for key, values := range r.PostForm {
			r.Form[key] = append(r.Form[key], values...)
		}

		if r.URL != nil {
			query, queryErr := url.ParseQuery(r.URL.RawQuery)
			if err == nil {
				err = queryErr
			}

			for key, values := range query {
				r.Form[key] = append(r.Form[key], values...)
			}
		}
	}

	return err
}

func parsePostForm(r *Request) (url.Values, error) {
	if r.Body == nil {
		return nil, errors.New("missing form body")
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	if mediaType != "application/x-www-form-urlencoded" {
		return nil, nil
	}

	var reader io.Reader = r.Body

	limit := int64(1<<63 - 1)

	if _, ok := r.Body.(*maxBytesReader); !ok {
		limit = maxFormSize
		reader = io.LimitReader(r.Body, limit+1)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > limit {
		return nil, errors.New("http: POST too large")
	}

	return url.ParseQuery(string(data))
}

// MaxBytesError is returned by a MaxBytesReader once the limit is exceeded.
type MaxBytesError struct {
	Limit int64
}

func (e *MaxBytesError) Error() string {
	return "http: request body too large"
}

type maxBytesReader struct {
	reader io.ReadCloser
	left   int64
	limit  int64
	err    error
}

// MaxBytesReader limits how much of body can be read. The ResponseWriter
// argument exists for net/http signature compatibility and is unused.
func MaxBytesReader(
	_ ResponseWriter,
	body io.ReadCloser,
	limit int64,
) io.ReadCloser {
	if limit < 0 {
		limit = 0
	}

	return &maxBytesReader{reader: body, left: limit, limit: limit}
}

func (m *maxBytesReader) Read(p []byte) (int, error) {
	if m.err != nil {
		return 0, m.err
	}

	if len(p) == 0 {
		return 0, nil
	}

	if int64(len(p))-1 > m.left {
		p = p[:m.left+1]
	}

	n, err := m.reader.Read(p)

	if int64(n) <= m.left {
		m.left -= int64(n)
		m.err = err

		return n, err
	}

	n = int(m.left)
	m.left = 0
	m.err = &MaxBytesError{Limit: m.limit}

	return n, m.err
}

func (m *maxBytesReader) Close() error {
	return m.reader.Close()
}
