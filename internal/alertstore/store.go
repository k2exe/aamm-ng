package alertstore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

const MaxLegacyBytes = 64 * 1024

var (
	ErrInvalidRoot       = errors.New("invalid alert directory")
	ErrInvalidBackupRoot = errors.New("invalid backup directory")
	ErrInvalidTarget     = errors.New("invalid alert target")
	ErrInvalidMessage    = errors.New("invalid alert message")
	ErrLegacyConflict    = errors.New("legacy alert requires explicit conversion")
	ErrOversizedConflict = errors.New("oversized alert requires explicit conversion")
	ErrUnsafeFile        = errors.New("alert file is not a regular file")
	ErrClosed            = errors.New("alert store is closed")
)

type Kind uint8

const (
	KindManaged Kind = iota + 1
	KindLegacy
	KindOversized
)

type Entry struct {
	Target     alerttarget.Target
	Kind       Kind
	Message    alertmessage.Message
	LegacyHTML string
	Size       int64
}

type Config struct {
	AlertRoot  string
	BackupRoot string
}

type Store struct {
	mu         sync.RWMutex
	alertRoot  *os.Root
	backupRoot *os.Root
}

func Open(config Config) (*Store, error) {
	alertRoot, err := openRoot(config.AlertRoot, ErrInvalidRoot, 0)
	if err != nil {
		return nil, err
	}

	backupRoot, err := openRoot(
		config.BackupRoot,
		ErrInvalidBackupRoot,
		0o700,
	)
	if err != nil {
		_ = alertRoot.Close()
		return nil, err
	}

	return &Store{
		alertRoot:  alertRoot,
		backupRoot: backupRoot,
	}, nil
}

func openRoot(
	path string,
	invalidError error,
	requiredMode os.FileMode,
) (*os.Root, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path is empty", invalidError)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", invalidError, path, err)
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: %s", invalidError, path)
	}

	if requiredMode != 0 && info.Mode().Perm() != requiredMode {
		return nil, fmt.Errorf(
			"%w: %s has mode %04o; want %04o",
			invalidError,
			path,
			info.Mode().Perm(),
			requiredMode,
		)
	}

	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", invalidError, path, err)
	}

	openedInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("%w: %s: %w", invalidError, path, err)
	}

	if !os.SameFile(info, openedInfo) {
		_ = root.Close()
		return nil, fmt.Errorf(
			"%w: directory changed while opening: %s",
			invalidError,
			path,
		)
	}

	return root, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var closeErrors []error

	if s.alertRoot != nil {
		closeErrors = append(closeErrors, s.alertRoot.Close())
		s.alertRoot = nil
	}

	if s.backupRoot != nil {
		closeErrors = append(closeErrors, s.backupRoot.Close())
		s.backupRoot = nil
	}

	return errors.Join(closeErrors...)
}

func (s *Store) Read(target alerttarget.Target) (Entry, error) {
	if target.String() == "" || target.Filename() == "" {
		return Entry{}, ErrInvalidTarget
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.alertRoot == nil {
		return Entry{}, ErrClosed
	}

	return readEntry(s.alertRoot, target)
}

func (s *Store) Write(
	target alerttarget.Target,
	message alertmessage.Message,
) error {
	if target.String() == "" || target.Filename() == "" {
		return ErrInvalidTarget
	}

	if message.String() == "" {
		return ErrInvalidMessage
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.alertRoot == nil {
		return ErrClosed
	}

	if err := ensureManagedWritable(s.alertRoot, target); err != nil {
		return err
	}

	return writeManaged(s.alertRoot, target, message)
}

func readEntry(
	root *os.Root,
	target alerttarget.Target,
) (Entry, error) {
	name := target.Filename()

	info, err := root.Lstat(name)
	if err != nil {
		return Entry{}, fmt.Errorf(
			"inspect alert %q: %w",
			target.String(),
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Entry{}, fmt.Errorf("%w: %s", ErrUnsafeFile, name)
	}

	file, err := root.Open(name)
	if err != nil {
		return Entry{}, fmt.Errorf(
			"open alert %q: %w",
			target.String(),
			err,
		)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return Entry{}, fmt.Errorf(
			"inspect open alert %q: %w",
			target.String(),
			err,
		)
	}

	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return Entry{}, fmt.Errorf("%w: %s", ErrUnsafeFile, name)
	}

	if openedInfo.Size() > MaxLegacyBytes {
		return Entry{
			Target: target,
			Kind:   KindOversized,
			Size:   openedInfo.Size(),
		}, nil
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxLegacyBytes+1))
	if err != nil {
		return Entry{}, fmt.Errorf(
			"read alert %q: %w",
			target.String(),
			err,
		)
	}

	if len(data) > MaxLegacyBytes {
		size := int64(len(data))

		if currentInfo, statErr := file.Stat(); statErr == nil &&
			currentInfo.Size() > size {
			size = currentInfo.Size()
		}

		return Entry{
			Target: target,
			Kind:   KindOversized,
			Size:   size,
		}, nil
	}

	message, managed := alertmessage.ParseManagedHTML(string(data))
	if managed {
		return Entry{
			Target:  target,
			Kind:    KindManaged,
			Message: message,
			Size:    int64(len(data)),
		}, nil
	}

	return Entry{
		Target:     target,
		Kind:       KindLegacy,
		LegacyHTML: string(data),
		Size:       int64(len(data)),
	}, nil
}

func ensureManagedWritable(
	root *os.Root,
	target alerttarget.Target,
) error {
	entry, err := readEntry(root, target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	switch entry.Kind {
	case KindManaged:
		return nil

	case KindLegacy:
		return fmt.Errorf(
			"%w: %s",
			ErrLegacyConflict,
			target.String(),
		)

	case KindOversized:
		return fmt.Errorf(
			"%w: %s",
			ErrOversizedConflict,
			target.String(),
		)

	default:
		return fmt.Errorf(
			"unsupported alert kind for %q",
			target.String(),
		)
	}
}

func writeManaged(
	root *os.Root,
	target alerttarget.Target,
	message alertmessage.Message,
) error {
	file, temporaryName, err := createTemporaryAlert(root)
	if err != nil {
		return fmt.Errorf(
			"create temporary alert %q: %w",
			target.String(),
			err,
		)
	}

	closed := false
	published := false

	defer func() {
		if !closed {
			_ = file.Close()
		}

		if !published {
			_ = root.Remove(temporaryName)
		}
	}()

	rendered := message.EscapedHTML()

	written, err := io.WriteString(file, rendered)
	if err != nil {
		return fmt.Errorf(
			"write temporary alert %q: %w",
			target.String(),
			err,
		)
	}

	if written != len(rendered) {
		return fmt.Errorf(
			"write temporary alert %q: %w",
			target.String(),
			io.ErrShortWrite,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync temporary alert %q: %w",
			target.String(),
			err,
		)
	}

	if err := file.Chmod(0o644); err != nil {
		return fmt.Errorf(
			"set alert permissions %q: %w",
			target.String(),
			err,
		)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"sync alert permissions %q: %w",
			target.String(),
			err,
		)
	}

	closeErr := file.Close()
	closed = true

	if closeErr != nil {
		return fmt.Errorf(
			"close temporary alert %q: %w",
			target.String(),
			closeErr,
		)
	}

	// Recheck immediately before replacement so a legacy, oversized,
	// symlinked, or otherwise unsafe file is not knowingly overwritten.
	if err := ensureManagedWritable(root, target); err != nil {
		return err
	}

	if err := root.Rename(temporaryName, target.Filename()); err != nil {
		return fmt.Errorf(
			"publish alert %q: %w",
			target.String(),
			err,
		)
	}

	published = true

	if err := syncDirectory(root); err != nil {
		return fmt.Errorf(
			"sync alert directory after writing %q: %w",
			target.String(),
			err,
		)
	}

	return nil
}

func createTemporaryAlert(root *os.Root) (*os.File, string, error) {
	for range 10 {
		randomBytes := make([]byte, 16)

		if _, err := rand.Read(randomBytes); err != nil {
			return nil, "", err
		}

		name := ".aamm-ng-" + hex.EncodeToString(randomBytes) + ".tmp"

		file, err := root.OpenFile(
			name,
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			0o600,
		)
		if errors.Is(err, os.ErrExist) {
			continue
		}

		if err != nil {
			return nil, "", err
		}

		return file, name, nil
	}

	return nil, "", errors.New(
		"could not allocate a unique temporary alert file",
	)
}

func syncDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}

	syncErr := directory.Sync()
	closeErr := directory.Close()

	return errors.Join(syncErr, closeErr)
}
