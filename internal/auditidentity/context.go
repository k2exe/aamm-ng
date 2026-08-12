package auditidentity

import "context"

// SourceIPHeader carries the validated source address from the CGI bridge
// to the loopback-only web service. The CGI bridge must ignore a
// browser-supplied copy of this header.
const SourceIPHeader = "X-AAMM-Remote-Addr"

type Identity struct {
	Name     string
	SourceIP string
}

type contextKey struct{}

func WithIdentity(
	ctx context.Context,
	identity Identity,
) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

func FromContext(
	ctx context.Context,
) (Identity, bool) {
	if ctx == nil {
		return Identity{}, false
	}

	identity, ok := ctx.Value(contextKey{}).(Identity)
	if !ok || identity.Name == "" {
		return Identity{}, false
	}

	return identity, true
}
