package alerttarget

import (
	"errors"
	"strings"
)

const MaxLength = 63

var ErrInvalid = errors.New("invalid alert target")

type target string

func Parse(value string) (target, error) {
	if value == "" || len(value) > MaxLength {
		return "", ErrInvalid
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

		return "", ErrInvalid
	}

	return target(value), nil
}

func (t target) String() string {
	return string(t)
}

func (t target) Filename() string {
	return string(t) + ".txt"
}

func isLetterOrDigit(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9'
}
