package alertmessage

import (
	"errors"
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxBytes = 4096

var (
	ErrEmpty            = errors.New("alert message is empty")
	ErrTooLarge         = errors.New("alert message is too large")
	ErrInvalidUTF8      = errors.New("alert message is not valid UTF-8")
	ErrControlCharacter = errors.New("alert message contains a control character")
)

type Message struct {
	value string
}

func Parse(value string) (Message, error) {
	if len(value) > MaxBytes {
		return Message{}, ErrTooLarge
	}

	if !utf8.ValidString(value) {
		return Message{}, ErrInvalidUTF8
	}

	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")

	if strings.TrimSpace(value) == "" {
		return Message{}, ErrEmpty
	}

	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}

		if unicode.IsControl(character) {
			return Message{}, ErrControlCharacter
		}
	}

	return Message{value: value}, nil
}

func (m Message) String() string {
	return m.value
}

func (m Message) EscapedHTML() string {
	escaped := html.EscapeString(m.value)
	return strings.ReplaceAll(escaped, "\n", "<br>\n")
}
