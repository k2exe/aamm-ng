package alertmessage

import (
	"errors"
	"strings"
	"testing"
)

func TestParseValidMessages(t *testing.T) {
	tests := map[string]string{
		"System maintenance":          "System maintenance",
		"Line one\r\nLine two":        "Line one\nLine two",
		"Line one\rLine two":          "Line one\nLine two",
		"Temperature: 21 °C":          "Temperature: 21 °C",
		"Column one\tColumn two":      "Column one\tColumn two",
		strings.Repeat("a", MaxBytes): strings.Repeat("a", MaxBytes),
	}

	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			message, err := Parse(input)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", input, err)
			}

			if message.String() != expected {
				t.Fatalf("Parse(%q) = %q; want %q", input, message, expected)
			}
		})
	}
}

func TestParseRejectsInvalidMessages(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{
			name:     "empty",
			input:    "",
			expected: ErrEmpty,
		},
		{
			name:     "blank",
			input:    " \t\r\n",
			expected: ErrEmpty,
		},
		{
			name:     "too large",
			input:    strings.Repeat("a", MaxBytes+1),
			expected: ErrTooLarge,
		},
		{
			name:     "invalid UTF-8",
			input:    string([]byte{0xff}),
			expected: ErrInvalidUTF8,
		},
		{
			name:     "NUL",
			input:    "hello\x00world",
			expected: ErrControlCharacter,
		},
		{
			name:     "ASCII control",
			input:    "hello\x01world",
			expected: ErrControlCharacter,
		},
		{
			name:     "DEL",
			input:    "hello\x7fworld",
			expected: ErrControlCharacter,
		},
		{
			name:     "Unicode control",
			input:    "hello\u0085world",
			expected: ErrControlCharacter,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, err := Parse(test.input)

			if !errors.Is(err, test.expected) {
				t.Fatalf("Parse() error = %v; want %v", err, test.expected)
			}

			if message != (Message{}) {
				t.Fatalf("Parse() message = %q; want zero value", message.String())
			}
		})
	}
}

func TestEscapedHTML(t *testing.T) {
	message, err := Parse(`<script>alert("x")</script>` + "\nSecond & final")
	if err != nil {
		t.Fatal(err)
	}

	const expected = `&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;<br>` +
		"\nSecond &amp; final"

	if message.EscapedHTML() != expected {
		t.Fatalf("EscapedHTML() = %q; want %q", message.EscapedHTML(), expected)
	}
}

func TestZeroValue(t *testing.T) {
	var message Message

	if message.String() != "" {
		t.Fatalf("String() = %q; want empty string", message.String())
	}

	if message.EscapedHTML() != "" {
		t.Fatalf("EscapedHTML() = %q; want empty string", message.EscapedHTML())
	}
}

func TestParseManagedHTML(t *testing.T) {
	tests := map[string]string{
		"Maintenance":                  "Maintenance",
		"Maintenance &amp; testing":    "Maintenance & testing",
		"&lt;b&gt;safe text&lt;/b&gt;": "<b>safe text</b>",
		"Line one<br>\nLine two":       "Line one\nLine two",
		"Temperature: 21 °C":           "Temperature: 21 °C",
	}

	for stored, expected := range tests {
		t.Run(stored, func(t *testing.T) {
			message, managed := ParseManagedHTML(stored)
			if !managed {
				t.Fatalf("ParseManagedHTML(%q) classified canonical content as legacy", stored)
			}

			if message.String() != expected {
				t.Fatalf("ParseManagedHTML(%q) = %q; want %q", stored, message.String(), expected)
			}

			if message.EscapedHTML() != stored {
				t.Fatalf("EscapedHTML() = %q; want exact input %q", message.EscapedHTML(), stored)
			}
		})
	}
}

func TestParseManagedHTMLRejectsLegacyContent(t *testing.T) {
	tests := []string{
		"",
		"<b>Emergency Net</b>",
		"Line one<br>Line two",
		"Line one<br/>Line two",
		"Line one<br />Line two",
		"Maintenance &quot;now&quot;",
		"Line one<br>\r\nLine two",
	}

	for _, stored := range tests {
		t.Run(stored, func(t *testing.T) {
			message, managed := ParseManagedHTML(stored)

			if managed {
				t.Fatalf("ParseManagedHTML(%q) classified legacy content as managed", stored)
			}

			if message != (Message{}) {
				t.Fatalf("ParseManagedHTML(%q) returned nonzero message %q", stored, message.String())
			}
		})
	}
}
