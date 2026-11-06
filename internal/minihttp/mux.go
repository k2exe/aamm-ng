package minihttp

import (
	"fmt"
	"html"
	"net/url"
	"path"
	"strings"
)

// ServeMux routes by path. It supports the subset of Go 1.22 patterns that
// AAMM-NG uses: literal segments, single-segment {name} wildcards and a
// trailing "/" for a subtree. Method and host patterns are not supported.
type ServeMux struct {
	routes []route
}

type route struct {
	pattern string
	segs    []segment
	subtree bool
	handler Handler
	score   int
}

type segment struct {
	literal  string
	wildcard string
}

func NewServeMux() *ServeMux {
	return &ServeMux{}
}

func (m *ServeMux) HandleFunc(
	pattern string,
	handler func(ResponseWriter, *Request),
) {
	m.Handle(pattern, HandlerFunc(handler))
}

func (m *ServeMux) Handle(pattern string, handler Handler) {
	if !strings.HasPrefix(pattern, "/") || handler == nil {
		panic(fmt.Sprintf("minihttp: invalid pattern %q", pattern))
	}

	subtree := strings.HasSuffix(pattern, "/")
	trimmed := strings.Trim(pattern, "/")

	var segs []segment

	if trimmed != "" {
		for _, part := range strings.Split(trimmed, "/") {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				segs = append(segs, segment{wildcard: part[1 : len(part)-1]})
				continue
			}

			segs = append(segs, segment{literal: part})
		}
	}

	score := len(segs)

	for _, seg := range segs {
		if seg.wildcard == "" {
			score += 10
		}
	}

	if !subtree {
		score += 1000
	}

	m.routes = append(m.routes, route{
		pattern: pattern,
		segs:    segs,
		subtree: subtree,
		handler: handler,
		score:   score,
	})
}

func (m *ServeMux) ServeHTTP(w ResponseWriter, r *Request) {
	requestPath := r.URL.Path

	if cleaned := cleanPath(requestPath); cleaned != requestPath {
		target := cleaned
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		Redirect(w, r, target, StatusMovedPermanently)

		return
	}

	best, values := m.match(r.URL.EscapedPath())
	if best == nil {
		NotFound(w, r)
		return
	}

	// "/dir" with only "/dir/" registered redirects to the subtree root.
	if best.pattern == "/" || best.subtree {
		if !strings.HasSuffix(requestPath, "/") {
			for i := range m.routes {
				if m.routes[i].pattern == requestPath+"/" &&
					m.routes[i].pattern != best.pattern {
					Redirect(w, r, requestPath+"/", StatusMovedPermanently)
					return
				}
			}
		}
	}

	if len(values) > 0 {
		r.pathValues = values
	}

	best.handler.ServeHTTP(w, r)
}

func (m *ServeMux) match(escapedPath string) (*route, map[string]string) {
	parts := strings.Split(strings.TrimPrefix(escapedPath, "/"), "/")

	var (
		best       *route
		bestValues map[string]string
	)

	for i := range m.routes {
		candidate := &m.routes[i]

		values, ok := candidate.matches(parts)
		if !ok {
			continue
		}

		if best == nil || candidate.score > best.score {
			best = candidate
			bestValues = values
		}
	}

	return best, bestValues
}

func (rt *route) matches(parts []string) (map[string]string, bool) {
	if rt.subtree {
		if len(parts) < len(rt.segs)+1 && len(rt.segs) > 0 {
			return nil, false
		}
	} else if len(parts) != len(rt.segs) {
		return nil, false
	}

	var values map[string]string

	for i, seg := range rt.segs {
		part, err := url.PathUnescape(parts[i])
		if err != nil {
			return nil, false
		}

		if seg.wildcard == "" {
			if seg.literal != part {
				return nil, false
			}

			continue
		}

		if part == "" {
			return nil, false
		}

		if values == nil {
			values = make(map[string]string)
		}

		values[seg.wildcard] = part
	}

	return values, true
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}

	if p[0] != '/' {
		p = "/" + p
	}

	cleaned := path.Clean(p)

	if p[len(p)-1] == '/' && cleaned != "/" {
		cleaned += "/"
	}

	return cleaned
}

// Error replies with a plain-text error message.
func Error(w ResponseWriter, message string, code int) {
	header := w.Header()
	header.Del("Content-Length")
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = fmt.Fprintln(w, message)
}

// NotFound replies with a 404.
func NotFound(w ResponseWriter, _ *Request) {
	Error(w, "404 page not found", StatusNotFound)
}

// Redirect replies with a redirect to target (resolved against the request
// path when relative).
func Redirect(w ResponseWriter, r *Request, target string, code int) {
	if parsed, err := url.Parse(target); err == nil &&
		parsed.Scheme == "" && parsed.Host == "" {
		oldPath := r.URL.Path
		if oldPath == "" {
			oldPath = "/"
		}

		oldPath = strings.TrimSuffix(oldPath, "/")

		switch {
		case target == "":
			target = oldPath
		case target[0] != '/':
			dir, _ := path.Split(r.URL.Path)
			target = dir + target
		}

		query := ""
		if i := strings.IndexByte(target, '?'); i >= 0 {
			target, query = target[:i], target[i:]
		}

		trailing := strings.HasSuffix(target, "/")

		target = path.Clean(target)
		if trailing && !strings.HasSuffix(target, "/") {
			target += "/"
		}

		target += query
	}

	header := w.Header()

	_, hadContentType := header["Content-Type"]

	header.Set("Location", escapeNonASCII(target))

	if !hadContentType && (r.Method == MethodGet || r.Method == MethodHead) {
		header.Set("Content-Type", "text/html; charset=utf-8")
	}

	w.WriteHeader(code)

	if !hadContentType && r.Method == MethodGet {
		_, _ = fmt.Fprint(
			w,
			"<a href=\""+html.EscapeString(target)+"\">"+
				StatusText(code)+"</a>.\n",
		)
	}
}

func escapeNonASCII(s string) string {
	var builder strings.Builder

	for i := 0; i < len(s); i++ {
		c := s[i]

		if c >= 0x80 || c < 0x20 || c == 0x7f {
			fmt.Fprintf(&builder, "%%%02X", c)
			continue
		}

		builder.WriteByte(c)
	}

	return builder.String()
}
