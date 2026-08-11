package auditidentity

import (
	"context"
	"testing"
)

func TestIdentityRoundTrip(t *testing.T) {
	ctx := WithIdentity(
		context.Background(),
		Identity{Name: "TEST-NODE-A"},
	)

	identity, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext() did not return identity")
	}

	if identity.Name != "TEST-NODE-A" {
		t.Fatalf(
			"identity name = %q; want TEST-NODE-A",
			identity.Name,
		)
	}
}

func TestIdentityMissing(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("FromContext() returned unexpected identity")
	}

	if _, ok := FromContext(nil); ok {
		t.Fatal("FromContext(nil) returned unexpected identity")
	}
}
