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
		"K2EXE-HAP-RB":                 "k2exe-hap-rb",
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

			if target != "" {
				t.Fatalf("Parse(%q) target = %q; want empty target", input, target)
			}
		})
	}
}

func TestFilename(t *testing.T) {
	target, err := Parse("K2EXE-HAP-RB")
	if err != nil {
		t.Fatal(err)
	}

	const expected = "k2exe-hap-rb.txt"

	if target.Filename() != expected {
		t.Fatalf("Filename() = %q; want %q", target.Filename(), expected)
	}
}
