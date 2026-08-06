package alertstore

import (
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

	name := target.Filename()

	info, err := s.alertRoot.Lstat(name)
	if err != nil {
		return Entry{}, fmt.Errorf("inspect alert %q: %w", target.String(), err)
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Entry{}, fmt.Errorf("%w: %s", ErrUnsafeFile, name)
	}

	file, err := s.alertRoot.Open(name)
	if err != nil {
		return Entry{}, fmt.Errorf("open alert %q: %w", target.String(), err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return Entry{}, fmt.Errorf("inspect open alert %q: %w", target.String(), err)
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
		return Entry{}, fmt.Errorf("read alert %q: %w", target.String(), err)
	}

	if len(data) > MaxLegacyBytes {
		size := int64(len(data))

		if currentInfo, statErr := file.Stat(); statErr == nil && currentInfo.Size() > size {
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
