package auditidentity

import (
	"context"
	"testing"
)

func TestIdentityRoundTrip(t *testing.T) {
	ctx := WithIdentity(
		context.Background(),
		Identity{Name: "K2EXE"},
	)

	identity, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext() did not return identity")
	}

	if identity.Name != "K2EXE" {
		t.Fatalf(
			"identity name = %q; want K2EXE",
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
