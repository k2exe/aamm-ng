# AAMM-NG Security Review Instructions

Review AAMM-NG as a privileged service that runs on AREDN and OpenWrt nodes.

Give priority to security, authorization, persistence, upgrade safety, and data integrity.

## Authentication

Treat `authV1` as credential-equivalent data.

`authV1` is derived from privileged AREDN authentication data.

Never recommend that AAMM-NG:

- logs `authV1`
- stores `authV1`
- includes `authV1` in an error
- sends `authV1` to a configurable endpoint
- sends `authV1` to a non-loopback endpoint

Production authentication must use the fixed AREDN verifier at:

`http://127.0.0.1/a/whoami`

Trust an AREDN user name only when `/a/whoami` reports an authenticated session.

Authentication errors must fail closed.

Do not trust `X-Forwarded-For`, `X-Real-IP`, or other browser-controlled headers for audit identity.

Flag any new source-identity mechanism that does not have a documented trusted boundary.

## Mutation authorization

Create, write, convert, and delete operations are mutations.

Each mutation must have an authenticated actor before it reaches the daemon mutation path.

Read and list operations must not gain mutation capability.

Flag any path that can change an alert without the authenticated mutation boundary.

## Audit logging

Successful and failed mutations must produce an audit record.

Audit records can contain:

- timestamp
- authenticated actor
- operation
- target
- outcome
- stable error code

Audit records must not contain:

- `authV1`
- cookies
- alert message contents
- raw sensitive request contents
- raw internal error messages that can expose sensitive data

Production audit output must remain compatible with the OpenWrt syslog path.

## Local control socket

The daemon control interface must remain a local Unix socket.

Do not replace it with a network listener without an explicit security design.

The runtime directory must preserve its restricted ownership and setgid behavior.

The control socket must preserve restricted group access.

Flag changes that weaken ownership, permissions, socket validation, or stale-socket safety.

## File safety

Alert targets must remain restricted to the approved target character set.

Flag path traversal, absolute paths, unexpected separators, Unicode control characters, and unsafe filename construction.

Preserve protection against symbolic-link attacks and file replacement races.

Preserve the use of rooted file access, `Lstat` checks, and file-identity revalidation where applicable.

## Backups

Persistent backups belong under:

`/etc/aamm-ng/backups`

Do not move persistent backups to `/var` or `/tmp`.

The backup directory must be created at runtime and must not become package-owned in a way that removes backups during uninstall and reinstall.

Preserve these properties:

- directory mode `0700`
- backup file mode `0600`
- maximum of 16 managed backup files
- bounded source reads and copies
- rejection of oversized legacy files
- no source mutation if backup creation or retention fails

Flag unbounded reads, unbounded backup growth, unsafe pruning, or package lifecycle changes that can remove backup data.

## Web exposure

The AAMM-NG administrator web service (`127.0.0.1:11313`) must remain bound to loopback unless a separate security design explicitly changes this requirement.

Do not recommend direct WAN, Internet, or mesh-wide exposure of the administrator listener.

Preserve Origin and authentication checks on mutating HTTP requests.

Flag changes that weaken CSRF protection or authentication.

The multi-user portal (`internal/portal`, port 11314) is the one approved exception. Its design is in `docs/portal.md` and `docs/audit-trust-boundary.md`. Flag any other new network listener.

## Multi-user portal

The portal is an exposed listener with its own login. Review every change to it against these rules. Flag any change that weakens one of them.

Reach and listener:

- The portal is off by default and starts only when settings turn it on.
- With reach `lan` it binds the node LAN address and must also refuse every connection whose peer is outside the node LAN network, because AREDN routes the LAN network across the mesh. It must fail closed when it cannot find the address or the network. It must never fall back to all addresses.
- The port is fixed at 11314 and matches the package firewall script.

Authority:

- The portal `Backend` interface must stay limited to login check, list, read, create, write, convert and delete. The portal must not import settings, user, storage, `webadmin`, `cgibridge` or `arednauth` code.
- The daemon decides authorization in `authorize`. It must deny by default. A portal identity must never be `admin`, and a viewer must never change an alert.
- Settings changes and all user operations are for the AREDN administrator only.
- The portal has no route for settings or users.

Identity and sessions:

- The source address is the TCP peer address only. Never read `X-Forwarded-For`, `X-Real-IP`, `Forwarded` or `X-AAMM-Remote-Addr` in the portal.
- Session tokens and CSRF tokens are random bytes from `/dev/urandom`. Never use `math/rand` for a secret.
- A login always issues a new token. Sessions expire when idle and have a maximum age. A session works only from its source address.
- A change to a user, and turning the portal off, must end the sessions.
- The cookie must stay `HttpOnly` and `SameSite=Strict`.
- Every state-changing request needs a same-origin check, and an authenticated one needs the session CSRF token.

Passwords:

- Store only salted PBKDF2-HMAC-SHA256 hashes, with the iteration count stored per hash and a minimum of 10,000.
- Never log, audit, return or reflect a password, a hash, or a salt.
- Return the same error for an unknown user, a disabled user and a wrong password, and hash in all cases.
- Compare in constant time. Run one hash at a time.
- Keep the login rate limit and lockout.

Output and input:

- Escape all output. Use no scripts and no resource from another site. Keep the security headers.
- Limit every body and header size. Accept exactly the fields a form expects.
- Show fixed error messages. Never show an internal error.

Cryptography:

- Code may import only `crypto/pbkdf2`, `crypto/sha256` and `crypto/subtle` from `crypto`. `scripts/check-crypto.sh` enforces this.
