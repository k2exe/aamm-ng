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
	ErrInvalidRoot   = errors.New("invalid alert directory")
	ErrInvalidTarget = errors.New("invalid alert target")
	ErrUnsafeFile    = errors.New("alert file is not a regular file")
	ErrClosed        = errors.New("alert store is closed")
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

type Store struct {
	mu   sync.RWMutex
	root *os.Root
}

func Open(path string) (*Store, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidRoot, path, err)
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRoot, path)
	}

	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidRoot, path, err)
	}

	openedInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidRoot, path, err)
	}

	if !os.SameFile(info, openedInfo) {
		_ = root.Close()
		return nil, fmt.Errorf("%w: directory changed while opening: %s", ErrInvalidRoot, path)
	}

	return &Store{root: root}, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.root == nil {
		return nil
	}

	err := s.root.Close()
	s.root = nil

	return err
}

func (s *Store) Read(target alerttarget.Target) (Entry, error) {
	if target.String() == "" || target.Filename() == "" {
		return Entry{}, ErrInvalidTarget
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.root == nil {
		return Entry{}, ErrClosed
	}

	name := target.Filename()

	info, err := s.root.Lstat(name)
	if err != nil {
		return Entry{}, fmt.Errorf("inspect alert %q: %w", target.String(), err)
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Entry{}, fmt.Errorf("%w: %s", ErrUnsafeFile, name)
	}

	file, err := s.root.Open(name)
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
