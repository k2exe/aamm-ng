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
	ErrFormatCharacter  = errors.New("alert message contains an unsupported Unicode format character")
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

	characters := []rune(value)

	for index, character := range characters {
		if character == '\n' || character == '\t' {
			continue
		}

		if unicode.IsControl(character) {
			return Message{}, ErrControlCharacter
		}

		if unicode.In(character, unicode.Cf) {
			if character == '\u200d' && validEmojiJoiner(characters, index) {
				continue
			}

			return Message{}, ErrFormatCharacter
		}
	}

	return Message{value: value}, nil
}

func validEmojiJoiner(characters []rune, index int) bool {
	left := index - 1

	for left >= 0 && isEmojiSequenceModifier(characters[left]) {
		left--
	}

	right := index + 1

	if left < 0 || right >= len(characters) {
		return false
	}

	return unicode.Is(unicode.So, characters[left]) &&
		unicode.Is(unicode.So, characters[right])
}

func isEmojiSequenceModifier(character rune) bool {
	if character == '\ufe0e' || character == '\ufe0f' {
		return true
	}

	return character >= '\U0001f3fb' && character <= '\U0001f3ff'
}

func (m Message) String() string {
	return m.value
}

func (m Message) EscapedHTML() string {
	escaped := html.EscapeString(m.value)
	return strings.ReplaceAll(escaped, "\n", "<br>\n")
}

// ParseManagedHTML accepts only the exact canonical representation generated
// by Message.EscapedHTML.
func ParseManagedHTML(value string) (Message, bool) {
	decoded := strings.ReplaceAll(value, "<br>\n", "\n")
	decoded = html.UnescapeString(decoded)

	message, err := Parse(decoded)
	if err != nil {
		return Message{}, false
	}

	if message.EscapedHTML() != value {
		return Message{}, false
	}

	return message, true
}
