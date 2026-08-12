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
