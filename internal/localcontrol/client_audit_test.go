package localcontrol

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/k2exe/aamm-ng/internal/arednsource"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
)

func testMutationAudit() *MutationAudit {
	return &MutationAudit{
		AuthNode:   "TEST-NODE-A",
		AuthRole:   "admin",
		SourceIP:   "192.0.2.44",
		SourceNode: "TEST-NODE-B",
		SourceHost: "test-workstation",
	}
}

func testRequiredMutationAudit() MutationAudit {
	return MutationAudit{
		AuthNode: "TEST-NODE-A",
		AuthRole: "admin",
		SourceIP: "192.0.2.44",
	}
}

func testResolvedSource(
	ctx context.Context,
	sourceIP string,
) (arednsource.Attribution, error) {
	if sourceIP != "192.0.2.44" {
		return arednsource.Attribution{}, fmt.Errorf(
			"source IP = %q; want 192.0.2.44",
			sourceIP,
		)
	}

	return arednsource.Attribution{
		SourceNode: "TEST-NODE-B",
		SourceHost: "test-workstation",
	}, nil
}

func validateTestRequestAudit(
	request Request,
	want MutationAudit,
) error {
	if request.Audit == nil {
		return errors.New("mutation request has no audit attribution")
	}

	if *request.Audit != want {
		return fmt.Errorf(
			"audit attribution = %#v; want %#v",
			*request.Audit,
			want,
		)
	}

	return nil
}

func testMutationContext() context.Context {
	return auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name:     "TEST-NODE-A",
			SourceIP: "192.0.2.44",
		},
	)
}

func TestMutationClientsRequireAuthenticatedIdentity(t *testing.T) {
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

	want := MutationAudit{
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

	want := MutationAudit{
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

func TestMutationAuditFromContextDropsInvalidOptionalAttribution(
	t *testing.T,
) {
	tests := []struct {
		name        string
		attribution arednsource.Attribution
		wantNode    string
		wantHost    string
	}{
		{
			name: "invalid source host preserves source node",
			attribution: arednsource.Attribution{
				SourceNode: "TEST-NODE-B",
				SourceHost: " bad-host",
			},
			wantNode: "TEST-NODE-B",
		},
		{
			name: "invalid source node drops optional attribution",
			attribution: arednsource.Attribution{
				SourceNode: "BAD\nNODE",
				SourceHost: "test-workstation",
			},
		},
		{
			name: "source host without source node is dropped",
			attribution: arednsource.Attribution{
				SourceHost: "test-workstation",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{
				resolveSource: func(
					context.Context,
					string,
				) (arednsource.Attribution, error) {
					return test.attribution, nil
				},
			}

			got, err := client.mutationAuditFromContext(
				testMutationContext(),
			)
			if err != nil {
				t.Fatalf(
					"mutationAuditFromContext returned error: %v",
					err,
				)
			}

			if got.AuthNode != "TEST-NODE-A" {
				t.Fatalf(
					"AuthNode = %q; want TEST-NODE-A",
					got.AuthNode,
				)
			}

			if got.AuthRole != "admin" {
				t.Fatalf(
					"AuthRole = %q; want admin",
					got.AuthRole,
				)
			}

			if got.SourceIP != "192.0.2.44" {
				t.Fatalf(
					"SourceIP = %q; want 192.0.2.44",
					got.SourceIP,
				)
			}

			if got.SourceNode != test.wantNode {
				t.Fatalf(
					"SourceNode = %q; want %q",
					got.SourceNode,
					test.wantNode,
				)
			}

			if got.SourceHost != test.wantHost {
				t.Fatalf(
					"SourceHost = %q; want %q",
					got.SourceHost,
					test.wantHost,
				)
			}
		})
	}
}

func TestMutationAuditEnrichesLocalSourceHostFromDHCP(t *testing.T) {
	lookupCalls := 0

	client := &Client{
		resolveSource: func(
			context.Context,
			string,
		) (arednsource.Attribution, error) {
			return arednsource.Attribution{
				SourceNode: "test-node-a",
			}, nil
		},
		lookupDHCPHost: func(sourceIP string) (string, error) {
			lookupCalls++

			if sourceIP != "192.0.2.44" {
				t.Fatalf(
					"DHCP source IP = %q; want 192.0.2.44",
					sourceIP,
				)
			}

			return "test-workstation", nil
		},
	}

	got, err := client.mutationAuditFromContext(
		testMutationContext(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if lookupCalls != 1 {
		t.Fatalf(
			"DHCP lookup calls = %d; want 1",
			lookupCalls,
		)
	}

	want := MutationAudit{
		AuthNode:   "TEST-NODE-A",
		AuthRole:   "admin",
		SourceIP:   "192.0.2.44",
		SourceNode: "test-node-a",
		SourceHost: "test-workstation",
	}

	if got != want {
		t.Fatalf(
			"audit = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestMutationAuditDoesNotUseDHCPForRemoteSource(t *testing.T) {
	client := &Client{
		resolveSource: func(
			context.Context,
			string,
		) (arednsource.Attribution, error) {
			return arednsource.Attribution{
				SourceNode: "TEST-NODE-B",
			}, nil
		},
		lookupDHCPHost: func(string) (string, error) {
			t.Fatal("DHCP lookup called for remote source")
			return "", nil
		},
	}

	got, err := client.mutationAuditFromContext(
		testMutationContext(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceHost != "" {
		t.Fatalf(
			"SourceHost = %q; want empty",
			got.SourceHost,
		)
	}
}

func TestMutationAuditKeepsPropagatedSourceHostBeforeDHCP(
	t *testing.T,
) {
	client := &Client{
		resolveSource: func(
			context.Context,
			string,
		) (arednsource.Attribution, error) {
			return arednsource.Attribution{
				SourceNode: "TEST-NODE-A",
				SourceHost: "propagated-workstation",
			}, nil
		},
		lookupDHCPHost: func(string) (string, error) {
			t.Fatal("DHCP lookup replaced propagated SourceHost")
			return "", nil
		},
	}

	got, err := client.mutationAuditFromContext(
		testMutationContext(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceHost != "propagated-workstation" {
		t.Fatalf(
			"SourceHost = %q; want propagated-workstation",
			got.SourceHost,
		)
	}
}

func TestMutationAuditTreatsDHCPFailureAsBestEffort(t *testing.T) {
	client := &Client{
		resolveSource: func(
			context.Context,
			string,
		) (arednsource.Attribution, error) {
			return arednsource.Attribution{
				SourceNode: "TEST-NODE-A",
			}, nil
		},
		lookupDHCPHost: func(string) (string, error) {
			return "", errors.New("synthetic DHCP failure")
		},
	}

	got, err := client.mutationAuditFromContext(
		testMutationContext(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceHost != "" {
		t.Fatalf(
			"SourceHost = %q; want empty",
			got.SourceHost,
		)
	}
}

func TestMutationAuditDropsUnsafeDHCPHostname(t *testing.T) {
	client := &Client{
		resolveSource: func(
			context.Context,
			string,
		) (arednsource.Attribution, error) {
			return arednsource.Attribution{
				SourceNode: "TEST-NODE-A",
			}, nil
		},
		lookupDHCPHost: func(string) (string, error) {
			return " bad-host", nil
		},
	}

	got, err := client.mutationAuditFromContext(
		testMutationContext(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceHost != "" {
		t.Fatalf(
			"SourceHost = %q; want empty",
			got.SourceHost,
		)
	}
}
