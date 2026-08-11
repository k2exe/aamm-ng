package arednhosts

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReaderReadsRegularFilesAndSkipsSymlinks(t *testing.T) {
	directory := t.TempDir()

	writeReaderTestFile(
		t,
		directory,
		"host-a",
		"record-a\n",
	)
	writeReaderTestFile(
		t,
		directory,
		"host-b",
		"record-b\n",
	)

	if err := os.Mkdir(
		filepath.Join(directory, "ignored-directory"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(
		filepath.Join(directory, "host-a"),
		filepath.Join(directory, "ignored-symlink"),
	); err != nil {
		t.Fatal(err)
	}

	reader := testRecordReader(directory)

	got, err := reader.read()
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"record-a\n",
		"record-b\n",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"records = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestReaderRejectsTooManyFiles(t *testing.T) {
	directory := t.TempDir()

	writeReaderTestFile(t, directory, "host-a", "a")
	writeReaderTestFile(t, directory, "host-b", "b")

	reader := testRecordReader(directory)
	reader.maxFiles = 1

	_, err := reader.read()

	if !errors.Is(err, ErrDataTooLarge) {
		t.Fatalf(
			"error = %v; want ErrDataTooLarge",
			err,
		)
	}
}

func TestReaderRejectsOversizedFile(t *testing.T) {
	directory := t.TempDir()

	writeReaderTestFile(
		t,
		directory,
		"host-a",
		"123456789",
	)

	reader := testRecordReader(directory)
	reader.maxFileBytes = 8

	_, err := reader.read()

	if !errors.Is(err, ErrDataTooLarge) {
		t.Fatalf(
			"error = %v; want ErrDataTooLarge",
			err,
		)
	}
}

func TestReaderRejectsOversizedAggregate(t *testing.T) {
	directory := t.TempDir()

	writeReaderTestFile(t, directory, "host-a", "12345")
	writeReaderTestFile(t, directory, "host-b", "67890")

	reader := testRecordReader(directory)
	reader.maxTotalBytes = 9

	_, err := reader.read()

	if !errors.Is(err, ErrDataTooLarge) {
		t.Fatalf(
			"error = %v; want ErrDataTooLarge",
			err,
		)
	}
}

func TestReaderReturnsReadErrorForMissingDirectory(t *testing.T) {
	reader := testRecordReader(
		filepath.Join(t.TempDir(), "missing"),
	)

	_, err := reader.read()

	if !errors.Is(err, ErrRead) {
		t.Fatalf(
			"error = %v; want ErrRead",
			err,
		)
	}
}

func testRecordReader(directory string) reader {
	return reader{
		directory:     directory,
		maxFiles:      16,
		maxFileBytes:  64 * 1024,
		maxTotalBytes: 256 * 1024,
	}
}

func writeReaderTestFile(
	t *testing.T,
	directory string,
	name string,
	content string,
) {
	t.Helper()

	if err := os.WriteFile(
		filepath.Join(directory, name),
		[]byte(content),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
}
