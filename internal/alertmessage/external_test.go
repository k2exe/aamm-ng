package alertmessage_test

import (
	"testing"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
)

func TestPublicAPI(t *testing.T) {
	message, err := alertmessage.Parse("Maintenance <complete>")
	if err != nil {
		t.Fatal(err)
	}

	if message.String() != "Maintenance <complete>" {
		t.Fatalf("String() = %q", message.String())
	}

	if message.EscapedHTML() != "Maintenance &lt;complete&gt;" {
		t.Fatalf("EscapedHTML() = %q", message.EscapedHTML())
	}
}

func TestManagedHTMLAPI(t *testing.T) {
	message, managed := alertmessage.ParseManagedHTML("Maintenance &amp; testing")
	if !managed {
		t.Fatal("canonical stored content classified as legacy")
	}

	if message.String() != "Maintenance & testing" {
		t.Fatalf("String() = %q", message.String())
	}
}
