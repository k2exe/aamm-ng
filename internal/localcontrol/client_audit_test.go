package localcontrol

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/k2exe/aamm-ng/internal/arednsource"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
)

func testMutationContext() context.Context {
	return auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name: "TEST-NODE-A",
		},
	)
}

func TestMutationClientsRequireAuthenticatedActor(t *testing.T) {
	client := &Client{
		socketPath: filepath.Join(
			t.TempDir(),
			"does-not-exist.sock",
		),
	}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "create",
			call: func() error {
				_, err := client.Create(
					context.Background(),
					"all",
					"Net open",
				)
				return err
			},
		},
		{
			name: "write",
			call: func() error {
				_, err := client.Write(
					context.Background(),
					"all",
					"Net open",
				)
				return err
			},
		},
		{
			name: "convert",
			call: func() error {
				_, err := client.Convert(
					context.Background(),
					"all",
					"Replacement",
				)
				return err
			},
		},
		{
			name: "delete",
			call: func() error {
				_, err := client.Delete(
					context.Background(),
					"all",
				)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()

			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf(
					"error = %v; want ErrInvalidRequest",
					err,
				)
			}
		})
	}
}

func TestSourceAttributionUsesConfiguredResolver(t *testing.T) {
	client := &Client{
		resolveSource: func(
			ctx context.Context,
			sourceIP string,
		) (arednsource.Attribution, error) {
			if sourceIP != "192.0.2.44" {
				t.Fatalf(
					"source IP = %q; want 192.0.2.44",
					sourceIP,
				)
			}

			return arednsource.Attribution{
				SourceNode: "TEST-NODE-B",
				SourceHost: "test-workstation",
			}, nil
		},
	}

	got := client.sourceAttribution(
		context.Background(),
		"192.0.2.44",
	)

	want := arednsource.Attribution{
		SourceNode: "TEST-NODE-B",
		SourceHost: "test-workstation",
	}

	if got != want {
		t.Fatalf(
			"attribution = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestSourceAttributionIsBestEffort(t *testing.T) {
	client := &Client{
		resolveSource: func(
			context.Context,
			string,
		) (arednsource.Attribution, error) {
			return arednsource.Attribution{},
				errors.New("lookup unavailable")
		},
	}

	got := client.sourceAttribution(
		context.Background(),
		"192.0.2.44",
	)

	if got != (arednsource.Attribution{}) {
		t.Fatalf(
			"attribution = %#v; want empty",
			got,
		)
	}
}

func TestSourceAttributionAllowsNilResolver(t *testing.T) {
	client := &Client{}

	got := client.sourceAttribution(
		context.Background(),
		"192.0.2.44",
	)

	if got != (arednsource.Attribution{}) {
		t.Fatalf(
			"attribution = %#v; want empty",
			got,
		)
	}
}

func TestMutationAuditFromContextBuildsAttribution(t *testing.T) {
	client := &Client{
		resolveSource: func(
			ctx context.Context,
			sourceIP string,
		) (arednsource.Attribution, error) {
			if sourceIP != "192.0.2.44" {
				t.Fatalf(
					"source IP = %q; want 192.0.2.44",
					sourceIP,
				)
			}

			return arednsource.Attribution{
				SourceNode: "TEST-NODE-B",
				SourceHost: "test-workstation",
			}, nil
		},
	}

	ctx := auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name:     "TEST-NODE-A",
			SourceIP: "192.0.2.44",
		},
	)

	got, err := client.mutationAuditFromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	want := mutationAuditContext{
		AuthNode:   "TEST-NODE-A",
		AuthRole:   "admin",
		SourceIP:   "192.0.2.44",
		SourceNode: "TEST-NODE-B",
		SourceHost: "test-workstation",
	}

	if got != want {
		t.Fatalf(
			"audit context = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestMutationAuditFromContextKeepsRequiredFieldsWhenLookupFails(
	t *testing.T,
) {
	client := &Client{
		resolveSource: func(
			context.Context,
			string,
		) (arednsource.Attribution, error) {
			return arednsource.Attribution{},
				errors.New("lookup unavailable")
		},
	}

	ctx := auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name:     "TEST-NODE-A",
			SourceIP: "192.0.2.44",
		},
	)

	got, err := client.mutationAuditFromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	want := mutationAuditContext{
		AuthNode: "TEST-NODE-A",
		AuthRole: "admin",
		SourceIP: "192.0.2.44",
	}

	if got != want {
		t.Fatalf(
			"audit context = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestMutationAuditFromContextCanonicalizesSourceAddress(t *testing.T) {
	client := &Client{}

	ctx := auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name:     "TEST-NODE-A",
			SourceIP: "::ffff:192.0.2.44",
		},
	)

	got, err := client.mutationAuditFromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceIP != "192.0.2.44" {
		t.Fatalf(
			"source IP = %q; want 192.0.2.44",
			got.SourceIP,
		)
	}
}

func TestMutationAuditFromContextRejectsMissingSourceAddress(t *testing.T) {
	client := &Client{}

	ctx := auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name: "TEST-NODE-A",
		},
	)

	_, err := client.mutationAuditFromContext(ctx)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf(
			"error = %v; want ErrInvalidRequest",
			err,
		)
	}
}
