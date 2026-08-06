package alerttarget

import (
	"errors"
	"strings"
)

const MaxLength = 63

var ErrInvalid = errors.New("invalid alert target")

type Target struct {
	value string
}

func Parse(value string) (Target, error) {
	if value == "" || len(value) > MaxLength {
		return Target{}, ErrInvalid
	}

	value = strings.ToLower(value)

	for i := 0; i < len(value); i++ {
		character := value[i]

		if isLetterOrDigit(character) {
			continue
		}

		if i > 0 && (character == '-' || character == '_') {
			continue
		}

		return Target{}, ErrInvalid
	}

	return Target{value: value}, nil
}

func (t Target) String() string {
	return t.value
}

func (t Target) Filename() string {
	if t.value == "" {
		return ""
	}

	return t.value + ".txt"
}

func isLetterOrDigit(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9'
}
