# No TLS, no cryptography

AAMM-NG links no TLS and no cryptographic code.

## Why

The Go `net/http` package imports `crypto/tls` and `crypto/x509`. The linker
keeps them even when a program never opens a TLS connection. On a router
these packages are a large part of the binary.

AAMM-NG never needs TLS:

- The web service listens only on `127.0.0.1:11313`.
- The CGI bridge talks to it over loopback.
- The AREDN authentication check goes to `http://127.0.0.1/a/whoami`.
- The browser connects to the AREDN web server, not to AAMM-NG.

Amateur radio rules also restrict messages that obscure their meaning
(47 CFR 97.113(a)(4)), so avoiding encryption inside the application keeps the
question from coming up.

## What replaced it

`internal/minihttp` provides the small part of `net/http` that AAMM-NG uses:
a server, a client, a mux, cookies, form parsing and a recorder for tests.
It depends only on `net`, `bufio` and `net/url`.

It is strict and deliberately limited:

- Plain `http` only. An `https` URL is an error.
- One request per connection. Responses carry `Connection: close`.
- The server refuses `Transfer-Encoding`, duplicate or malformed
  `Content-Length`, folded headers, bare LF line endings, absolute-form
  targets and an `HTTP/1.1` request without `Host`.
- Header and body sizes, connection count and timeouts are bounded.
- The client never follows redirects, never uses proxies and refuses CR, LF
  and NUL in the `Host` header and in header values.
- The client decodes chunked and close-delimited responses.

## Other changes

- `alertstore` no longer uses `crypto/sha256` or `crypto/rand`. The
  source-changed check compares the file bytes (at most 64 KiB) instead of a
  digest. Temporary and backup names come from `math/rand/v2`; they are
  unique names, not secrets, and are created with `O_EXCL`.
- The same-origin check accepts only `http://<Host>`. The backend never sees
  TLS, so `request.TLS` was always nil in production.

## Guard

CI fails if `go list -deps` for either command shows `crypto/*`, `net/http`
or `golang.org/x/crypto`.
