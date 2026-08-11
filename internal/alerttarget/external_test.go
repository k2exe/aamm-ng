package alerttarget_test

import (
	"testing"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func TestPublicAPI(t *testing.T) {
	target, err := alerttarget.Parse("TEST-NODE-A")
	if err != nil {
		t.Fatal(err)
	}

	if target.String() != "test-node-a" {
		t.Fatalf("String() = %q", target.String())
	}

	if target.Filename() != "test-node-a.txt" {
		t.Fatalf("Filename() = %q", target.Filename())
	}
}
