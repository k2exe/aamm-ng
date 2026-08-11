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

The AAMM-NG web service must remain bound to loopback unless a separate security design explicitly changes this requirement.

Do not recommend direct WAN, Internet, or mesh-wide exposure of the management listener.

Preserve Origin and authentication checks on mutating HTTP requests.

Flag changes that weaken CSRF protection or authentication.
