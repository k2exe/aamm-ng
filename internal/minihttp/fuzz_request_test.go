package minihttp

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func FuzzReadRequest(f *testing.F) {
	seeds := []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"POST /login HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nabcde",
		"GET /a?b=c HTTP/1.0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n",
		"GET http://evil/ HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
		"GET / HTTP/1.1\nHost: a\n\n",
		"GET /\x00 HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
		"G\x00T / HTTP/1.1\r\nHost: a\r\n\r\n",
		"",
		"\r\n\r\n",
	}

	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bufio.NewReader(bytes.NewReader(data))

		request, err := readRequest(reader, 16<<10)
		if err != nil {
			return
		}

		// Anything accepted must follow the strict rules.
		if !isToken(request.Method) {
			t.Fatalf("accepted method %q", request.Method)
		}

		if request.URL == nil || !strings.HasPrefix(request.URL.EscapedPath(), "/") {
			t.Fatalf("accepted target %v", request.URL)
		}

		if len(request.Header.Values("Transfer-Encoding")) != 0 {
			t.Fatal("accepted a Transfer-Encoding header")
		}

		if len(request.Header.Values("Host")) > 1 {
			t.Fatal("accepted two Host headers")
		}

		if request.Host != "" && !validHost(request.Host) {
			t.Fatalf("accepted Host %q", request.Host)
		}

		for name, values := range request.Header {
			if !isToken(name) {
				t.Fatalf("accepted header name %q", name)
			}

			for _, value := range values {
				if !validFieldValue(value) {
					t.Fatalf("accepted header value %q", value)
				}
			}
		}

		if len(request.Header.Values("Content-Length")) > 1 {
			t.Fatal("accepted two Content-Length headers")
		}
	})
}
