package minihttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// parseError carries the HTTP status a server should answer with.
type parseError struct {
	status int
	msg    string
}

func (e *parseError) Error() string { return e.msg }

func badRequest(msg string) *parseError {
	return &parseError{status: StatusBadRequest, msg: msg}
}

// readLine reads one CRLF-terminated line of at most limit bytes (excluding
// CRLF). A bare LF, an over-long line or a NUL byte is an error: this parser
// is strict on purpose so that it cannot be desynchronised.
func readLine(br *bufio.Reader, limit int) (string, error) {
	var line []byte

	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)

		if len(line) > limit+2 {
			return "", &parseError{
				status: StatusHeaderFieldsTooLarg,
				msg:    "line too long",
			}
		}

		if err == nil {
			break
		}

		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}

		if errors.Is(err, io.EOF) && len(line) > 0 {
			return "", io.ErrUnexpectedEOF
		}

		return "", err
	}

	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", badRequest("line not terminated by CRLF")
	}

	line = line[:len(line)-2]

	if bytes.IndexByte(line, 0) >= 0 {
		return "", badRequest("NUL byte in line")
	}

	return string(line), nil
}

// readHeader reads header fields up to the blank line. total bounds the
// combined size of all header lines.
func readHeader(br *bufio.Reader, total int) (Header, error) {
	header := make(Header)
	remaining := total

	for {
		line, err := readLine(br, remaining)
		if err != nil {
			return nil, err
		}

		if line == "" {
			return header, nil
		}

		remaining -= len(line) + 2
		if remaining < 0 {
			return nil, &parseError{
				status: StatusHeaderFieldsTooLarg,
				msg:    "headers too large",
			}
		}

		if line[0] == ' ' || line[0] == '\t' {
			return nil, badRequest("obsolete header line folding")
		}

		name, value, found := strings.Cut(line, ":")
		if !found || !isToken(name) {
			return nil, badRequest("malformed header line")
		}

		value = strings.Trim(value, " \t")
		if !validFieldValue(value) {
			return nil, badRequest("invalid header value")
		}

		header.Add(name, value)
	}
}

// parseContentLength returns the single Content-Length of header, -1 if it is
// absent. Duplicates, signs and non-digits are rejected.
func parseContentLength(header Header) (int64, error) {
	values := header.Values("Content-Length")

	switch len(values) {
	case 0:
		return -1, nil
	case 1:
	default:
		return 0, badRequest("multiple Content-Length headers")
	}

	value := values[0]
	if value == "" || len(value) > 18 {
		return 0, badRequest("invalid Content-Length")
	}

	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, badRequest("invalid Content-Length")
		}
	}

	length, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, badRequest("invalid Content-Length")
	}

	return length, nil
}

// parseVersion accepts only HTTP/1.0 and HTTP/1.1.
func parseVersion(version string) (minor int, ok bool) {
	switch version {
	case "HTTP/1.0":
		return 0, true
	case "HTTP/1.1":
		return 1, true
	}

	return 0, false
}

// bodyReader returns exactly length bytes or io.ErrUnexpectedEOF.
type bodyReader struct {
	reader io.Reader
	left   int64
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, io.EOF
	}

	if int64(len(p)) > b.left {
		p = p[:b.left]
	}

	n, err := b.reader.Read(p)
	b.left -= int64(n)

	if errors.Is(err, io.EOF) && b.left > 0 {
		err = io.ErrUnexpectedEOF
	}

	if err == nil && b.left == 0 {
		err = io.EOF
	}

	return n, err
}

// chunkedReader decodes a chunked transfer coding (client side only).
type chunkedReader struct {
	br   *bufio.Reader
	left int64
	done bool
	err  error
}

func newChunkedReader(br *bufio.Reader) *chunkedReader {
	return &chunkedReader{br: br}
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}

	for c.left == 0 {
		if c.done {
			c.err = io.EOF
			return 0, c.err
		}

		if err := c.nextChunk(); err != nil {
			c.err = err
			return 0, err
		}
	}

	if int64(len(p)) > c.left {
		p = p[:c.left]
	}

	n, err := c.br.Read(p)
	c.left -= int64(n)

	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}

	if err != nil {
		c.err = err
		return n, err
	}

	if c.left == 0 {
		if err := c.expectCRLF(); err != nil {
			c.err = err
			return n, err
		}
	}

	return n, nil
}

func (c *chunkedReader) expectCRLF() error {
	line, err := readLine(c.br, 0)
	if err != nil {
		return noEOF(err)
	}

	if line != "" {
		return errors.New("http: malformed chunk terminator")
	}

	return nil
}

func (c *chunkedReader) nextChunk() error {
	line, err := readLine(c.br, 128)
	if err != nil {
		return noEOF(err)
	}

	sizeText, _, _ := strings.Cut(line, ";")
	sizeText = strings.TrimSpace(sizeText)

	if sizeText == "" || len(sizeText) > 15 {
		return errors.New("http: invalid chunk size")
	}

	size, err := strconv.ParseUint(sizeText, 16, 62)
	if err != nil {
		return errors.New("http: invalid chunk size")
	}

	if size > 0 {
		c.left = int64(size)
		return nil
	}

	// Last chunk: discard (bounded) trailers up to the blank line.
	if _, err := readHeader(c.br, 8<<10); err != nil {
		return noEOF(err)
	}

	c.done = true

	return nil
}

func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}

	return err
}

// writeHeader serialises header fields in sorted order, dropping fields whose
// name is not a token and flattening CR/LF in values (response splitting).
func writeHeader(w io.Writer, header Header, skip ...string) error {
	names := make([]string, 0, len(header))

	for name := range header {
		names = append(names, name)
	}

	slices.Sort(names)

next:
	for _, name := range names {
		if !isToken(name) {
			continue
		}

		for _, skipped := range skip {
			if strings.EqualFold(name, skipped) {
				continue next
			}
		}

		for _, value := range header[name] {
			value = strings.NewReplacer(
				"\r", " ",
				"\n", " ",
				"\x00", " ",
			).Replace(value)

			if _, err := fmt.Fprintf(w, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
	}

	return nil
}
