package alerttarget

import (
	"errors"
	"strings"
	"testing"
)

func TestParseValidTargets(t *testing.T) {
	tests := map[string]string{
		"all":                          "all",
		"weather":                      "weather",
		"group_1":                      "group_1",
		"TEST-NODE-A":                  "test-node-a",
		"node-123":                     "node-123",
		strings.Repeat("a", MaxLength): strings.Repeat("a", MaxLength),
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			target, err := Parse(input)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", input, err)
			}

			if target.String() != expected {
				t.Fatalf("Parse(%q) = %q; want %q", input, target, expected)
			}
		})
	}
}

func TestParseRejectsInvalidTargets(t *testing.T) {
	tests := []string{
		"",
		"-node",
		"_group",
		" node",
		"node ",
		"node name",
		"node.txt",
		".",
		"..",
		"../node",
		"/tmp/node",
		"node/child",
		`node\child`,
		"node%2fchild",
		"node;rm",
		"node&command",
		"<script>",
		"é",
		strings.Repeat("a", MaxLength+1),
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			target, err := Parse(input)

			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q) error = %v; want ErrInvalid", input, err)
			}

			if target != (Target{}) {
				t.Fatalf("Parse(%q) target = %q; want zero value", input, target.String())
			}
		})
	}
}

func TestFilename(t *testing.T) {
	target, err := Parse("TEST-NODE-A")
	if err != nil {
		t.Fatal(err)
	}

	const expected = "test-node-a.txt"

	if target.Filename() != expected {
		t.Fatalf("Filename() = %q; want %q", target.Filename(), expected)
	}
}

func TestZeroValue(t *testing.T) {
	var target Target

	if target.String() != "" {
		t.Fatalf("String() = %q; want empty string", target.String())
	}

	if target.Filename() != "" {
		t.Fatalf("Filename() = %q; want empty string", target.Filename())
	}
}
