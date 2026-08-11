package localcontrol

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/k2exe/aamm-ng/internal/auditidentity"
)

func testMutationContext() context.Context {
	return auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name: "K2EXE",
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
