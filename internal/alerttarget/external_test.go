package alerttarget_test

import (
	"testing"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

func TestPublicAPI(t *testing.T) {
	target, err := alerttarget.Parse("K2EXE-HAP-RB")
	if err != nil {
		t.Fatal(err)
	}

	if target.String() != "k2exe-hap-rb" {
		t.Fatalf("String() = %q", target.String())
	}

	if target.Filename() != "k2exe-hap-rb.txt" {
		t.Fatalf("Filename() = %q", target.Filename())
	}
}
