package auditidentity

import "context"

const SourceIPHeader = "X-AAMM-Remote-Addr"

type Identity struct {
	Name string
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
