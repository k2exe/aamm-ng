# Audit Identity Trust Boundary

AAMM-NG records an authenticated identity and source information for each
management change.

These values do not have the same trust level.

## Authenticated identity

`AuthNode` identifies the authenticated AREDN administrator.

AAMM-NG gets this identity from the AREDN authentication service.

Use `AuthNode` to identify the authenticated administrator.

Do not use source-attribution metadata as a replacement for authentication.

## Source IP address

`SourceIP` is the authoritative source-address field in the AAMM-NG audit
record.

It identifies the network source that the trusted CGI boundary reports.

It does not identify the authenticated administrator.

The AREDN web server supplies the client address in CGI `REMOTE_ADDR`.

The AAMM-NG CGI bridge validates this value as an IP address.

The CGI bridge then sets `X-AAMM-Remote-Addr` on the internal request.

The bridge ignores a browser-supplied copy of this header.

The bridge replaces it with the validated CGI `REMOTE_ADDR` value.

The AAMM-NG web service validates the header again before it creates the audit
identity.

The web service removes the header before it passes the request to the
application handler.

## Source node and source host

`SourceNode` and `SourceHost` are advisory display metadata.

AAMM-NG derives these values from AREDN host information and local DHCP data.

Mesh host information can contain data supplied by other mesh systems.

DHCP host names are also descriptive data.

Do not use `SourceNode` or `SourceHost` for authentication.

Do not use `SourceNode` or `SourceHost` for authorization.

Do not use these values as the only evidence for a security decision.

AAMM-NG can omit these values when it cannot resolve or validate them.

`SourceIP` remains the authoritative source address when this occurs.

## Security invariants

The production AAMM-NG web service must listen only on
`127.0.0.1:11313`.

The CGI bridge must be the network-facing path to this service.

The CGI bridge must get the source address from CGI `REMOTE_ADDR`.

The CGI bridge must ignore `X-AAMM-Remote-Addr` from browser input.

The CGI bridge must replace that value with validated CGI `REMOTE_ADDR`.

The web service must reject a missing or invalid internal source address.

Do not change the production listener to `0.0.0.0` or another network address
without a new source-identity security design.

A direct network listener would let a client supply the internal trust header
unless another trusted boundary replaced the CGI bridge.

## Multi-user portal

The multi-user portal (`docs/portal.md`) is a second listener. It is the
network listener that the text above warns about. It has its own source
identity design, which does not use the CGI bridge.

### Source address

The portal uses the address of the TCP connection as the source address. This
is `request.RemoteAddr`.

The portal never reads a source address from a header. It ignores
`X-AAMM-Remote-Addr`, `X-Forwarded-For`, `X-Real-IP` and `Forwarded`.

A test fails if the portal code reads one of these headers.

A client behind NAT on the node LAN appears with the node address. A client
that reaches the portal through a mesh router appears with its mesh address.

### Identity

A portal identity has `auth_method` set to `portal`. The role is `editor` or
`viewer`. A portal identity is never `admin`.

The portal user name is authenticated by the daemon, which checks the
password hash. The portal user name is not an AREDN node name. Do not use it
as one.

The AREDN administrator keeps the empty method (or `aredn`) and the role
`admin`. Only this identity may change settings and users.

### Daemon checks

The daemon decides what each identity may do. It does not trust the web
service to decide.

| Operation | AREDN admin | Portal editor | Portal viewer |
|---|---|---|---|
| list, read | yes | yes | yes |
| create, write, convert, delete | yes | yes | no |
| change settings, manage users | yes | no | no |

The daemon denies an operation that has no rule.

### Audit

Each portal login attempt writes an audit line. The line has the user name
that was tried, `auth_method="portal"`, the source address and the outcome.
It never has a password.

Each alert change by a portal user has `auth_method="portal"` and the
portal role.

### Listener rules

- The portal listens on port 11314 only when an administrator turns it on.
- With "LAN only", it listens on the node LAN address. If it cannot find this
  address, it does not listen.
- With "LAN and mesh", it listens on all addresses. The package opens the
  port in the mesh firewall.
- The administrator web service stays on `127.0.0.1:11313`.
