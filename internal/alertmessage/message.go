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

type message string

func Parse(value string) (message, error) {
	if len(value) > MaxBytes {
		return "", ErrTooLarge
	}

	if !utf8.ValidString(value) {
		return "", ErrInvalidUTF8
	}

	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")

	if strings.TrimSpace(value) == "" {
		return "", ErrEmpty
	}

	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}

		if unicode.IsControl(character) {
			return "", ErrControlCharacter
		}
	}

	return message(value), nil
}

func (m message) String() string {
	return string(m)
}

func (m message) EscapedHTML() string {
	escaped := html.EscapeString(string(m))
	return strings.ReplaceAll(escaped, "\n", "<br>\n")
}
