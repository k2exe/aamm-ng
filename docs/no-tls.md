# No TLS, password hashing only

AAMM-NG links no TLS and no public-key cryptography.

The only cryptography in AAMM-NG is password hashing for the multi-user
portal. See `docs/portal.md`.

## Why there is no TLS

The Go `net/http` package imports `crypto/tls` and `crypto/x509`. The linker
keeps them even when a program never opens a TLS connection. On a router
these packages are a large part of the binary.

The AREDN administrator UI never needs TLS:

- The web service listens only on `127.0.0.1:11313`.
- The CGI bridge talks to it over loopback.
- The AREDN authentication check goes to `http://127.0.0.1/a/whoami`.
- The browser connects to the AREDN web server, not to AAMM-NG.

The multi-user portal has its own port and does not use TLS. Its passwords
cross the network as plain text. See `docs/portal.md` for the reason and the
limits.

Amateur radio rules also restrict messages that obscure their meaning
(47 CFR 97.113(a)(4)). AAMM-NG does not encrypt any message.

## What replaced `net/http`

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

A fuzz test (`FuzzReadRequest`) checks the request parser.

## Password hashing

The portal stores each password only as a salted hash. AAMM-NG uses these
standard library packages for this:

| Package | Use |
|---|---|
| `crypto/pbkdf2` | PBKDF2 with HMAC-SHA-256 |
| `crypto/sha256` | the hash function |
| `crypto/subtle` | a constant-time compare |

AAMM-NG reads random bytes (salts, session tokens) from `/dev/urandom`. It
does not use `crypto/rand`.

### The Go FIPS module is linked

Any use of the Go standard library hashing links the Go FIPS 140 module
(`crypto/internal/fips140/...`). This module contains AES, SHA-3 and a random
bit generator. AAMM-NG never calls them. The linker cannot remove them.

This adds about 200 to 260 KB to each binary on 32-bit ARM. It cannot be
avoided with the standard library. The only other way is to write SHA-256 in
the AAMM-NG source, which this project has not done.

## Other changes

- `alertstore` does not use `crypto/sha256` or `crypto/rand`. The
  source-changed check compares the file bytes (at most 64 KiB) instead of a
  digest. Temporary and backup names come from `math/rand/v2`; they are
  unique names, not secrets, and are created with `O_EXCL`.
- The same-origin check of the administrator UI accepts only `http://<Host>`.
  The backend never sees TLS, so `request.TLS` was always nil in production.

## Guard

`scripts/check-crypto.sh` runs in CI. It fails if:

- AAMM-NG code imports a `crypto` package other than `crypto/pbkdf2`,
  `crypto/sha256` and `crypto/subtle`, or imports `net/http` or
  `golang.org/x/crypto`; or
- a command links TLS, X.509, public-key cryptography, a cipher package
  (`crypto/aes`, `crypto/des`, `crypto/rc4`), a legacy hash (`crypto/md5`,
  `crypto/sha1`), `crypto/rand` or `net/http`.

The script does not forbid the FIPS module code that hashing links.
