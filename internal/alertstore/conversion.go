package alertstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/k2exe/aamm-ng/internal/alertmessage"
	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

const maxBackupFiles = 16

type ConversionResult struct {
	BackupName string
}

type sourceSnapshot struct {
	info   os.FileInfo
	digest [sha256.Size]byte
}

func (s *Store) ConvertLegacy(
	target alerttarget.Target,
	message alertmessage.Message,
) (ConversionResult, error) {
	if target.String() == "" || target.Filename() == "" {
		return ConversionResult{}, ErrInvalidTarget
	}

	if message.String() == "" {
		return ConversionResult{}, ErrInvalidMessage
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.alertRoot == nil || s.backupRoot == nil {
		return ConversionResult{}, ErrClosed
	}

	snapshot, backupName, err := backupAlert(
		s.alertRoot,
		s.backupRoot,
		target,
		true,
	)
	if err != nil {
		return ConversionResult{}, err
	}

	check := func() error {
		return verifySourceUnchanged(
			s.alertRoot,
			target,
			snapshot,
		)
	}

	if err := writeManagedChecked(
		s.alertRoot,
		target,
		message,
		check,
	); err != nil {
		return ConversionResult{}, fmt.Errorf(
			"convert alert %q after backup %q: %w",
			target.String(),
			backupName,
			err,
		)
	}

	return ConversionResult{
		BackupName: backupName,
	}, nil
}

func backupAlert(
	alertRoot *os.Root,
	backupRoot *os.Root,
	target alerttarget.Target,
	rejectManaged bool,
) (sourceSnapshot, string, error) {
	name := target.Filename()

	info, err := alertRoot.Lstat(name)
	if err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"inspect alert %q for conversion: %w",
			target.String(),
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return sourceSnapshot{}, "", fmt.Errorf(
			"%w: %s",
			ErrUnsafeFile,
			name,
		)
	}

	source, err := alertRoot.Open(name)
	if err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"open alert %q for conversion: %w",
			target.String(),
			err,
		)
	}
	defer source.Close()

	openedInfo, err := source.Stat()
	if err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"inspect open alert %q for conversion: %w",
			target.String(),
			err,
		)
	}

	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return sourceSnapshot{}, "", fmt.Errorf(
			"%w: %s",
			ErrUnsafeFile,
			name,
		)
	}

	if openedInfo.Size() > MaxLegacyBytes {
		return sourceSnapshot{}, "", fmt.Errorf(
			"%w: %s",
			ErrOversizedConflict,
			target.String(),
		)
	}

	backup, temporaryName, err := createTemporaryBackup(backupRoot)
	if err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"create backup for alert %q: %w",
			target.String(),
			err,
		)
	}

	closed := false
	published := false

	defer func() {
		if !closed {
			_ = backup.Close()
		}

		if !published {
			_ = backupRoot.Remove(temporaryName)
		}
	}()

	hasher := sha256.New()
	capture := boundedCapture{
		limit: MaxLegacyBytes + 1,
	}

	copied, err := io.Copy(
		io.MultiWriter(backup, hasher, &capture),
		io.LimitReader(source, MaxLegacyBytes+1),
	)
	if err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"copy backup for alert %q: %w",
			target.String(),
			err,
		)
	}

	if copied > MaxLegacyBytes {
		return sourceSnapshot{}, "", fmt.Errorf(
			"%w: %s",
			ErrOversizedConflict,
			target.String(),
		)
	}

	sourceAfter, err := source.Stat()
	if err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"reinspect alert %q after backup: %w",
			target.String(),
			err,
		)
	}

	if !os.SameFile(openedInfo, sourceAfter) ||
		openedInfo.Size() != copied ||
		sourceAfter.Size() != copied ||
		!openedInfo.ModTime().Equal(sourceAfter.ModTime()) {
		return sourceSnapshot{}, "", fmt.Errorf(
			"%w: %s",
			ErrSourceChanged,
			name,
		)
	}

	if rejectManaged {
		_, managed := alertmessage.ParseManagedHTML(string(capture.data))
		if managed {
			return sourceSnapshot{}, "", fmt.Errorf(
				"%w: %s",
				ErrManagedConflict,
				target.String(),
			)
		}
	}

	if err := backup.Chmod(0o600); err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"set backup permissions for alert %q: %w",
			target.String(),
			err,
		)
	}

	if err := backup.Sync(); err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"sync backup for alert %q: %w",
			target.String(),
			err,
		)
	}

	closeErr := backup.Close()
	closed = true

	if closeErr != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"close backup for alert %q: %w",
			target.String(),
			closeErr,
		)
	}

	backupName, err := newBackupName(target)
	if err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"name backup for alert %q: %w",
			target.String(),
			err,
		)
	}

	if err := backupRoot.Rename(temporaryName, backupName); err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"publish backup for alert %q: %w",
			target.String(),
			err,
		)
	}

	published = true

	if err := syncDirectory(backupRoot); err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"sync backup directory for alert %q: %w",
			target.String(),
			err,
		)
	}

	if err := pruneBackups(backupRoot, backupName); err != nil {
		return sourceSnapshot{}, "", fmt.Errorf(
			"prune backups after creating %q: %w",
			backupName,
			err,
		)
	}

	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))

	return sourceSnapshot{
		info:   sourceAfter,
		digest: digest,
	}, backupName, nil
}

func verifySourceUnchanged(
	root *os.Root,
	target alerttarget.Target,
	snapshot sourceSnapshot,
) error {
	name := target.Filename()

	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf(
			"%w: inspect %s: %v",
			ErrSourceChanged,
			name,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!os.SameFile(snapshot.info, info) {
		return fmt.Errorf("%w: %s", ErrSourceChanged, name)
	}

	source, err := root.Open(name)
	if err != nil {
		return fmt.Errorf(
			"%w: open %s: %v",
			ErrSourceChanged,
			name,
			err,
		)
	}

	openedInfo, err := source.Stat()
	if err != nil {
		_ = source.Close()
		return fmt.Errorf(
			"%w: inspect open %s: %v",
			ErrSourceChanged,
			name,
			err,
		)
	}

	if !openedInfo.Mode().IsRegular() ||
		!os.SameFile(snapshot.info, openedInfo) {
		_ = source.Close()
		return fmt.Errorf("%w: %s", ErrSourceChanged, name)
	}

	hasher := sha256.New()

	copied, copyErr := io.Copy(
		hasher,
		io.LimitReader(source, MaxLegacyBytes+1),
	)
	afterInfo, statErr := source.Stat()
	closeErr := source.Close()

	if err := errors.Join(copyErr, statErr, closeErr); err != nil {
		return fmt.Errorf(
			"%w: verify %s: %v",
			ErrSourceChanged,
			name,
			err,
		)
	}

	if !os.SameFile(snapshot.info, afterInfo) ||
		copied != snapshot.info.Size() ||
		afterInfo.Size() != snapshot.info.Size() ||
		!afterInfo.ModTime().Equal(snapshot.info.ModTime()) {
		return fmt.Errorf("%w: %s", ErrSourceChanged, name)
	}

	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))

	if digest != snapshot.digest {
		return fmt.Errorf("%w: %s", ErrSourceChanged, name)
	}

	return nil
}

func pruneBackups(
	root *os.Root,
	protectedName string,
) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open backup directory: %w", err)
	}

	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()

	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("read backup directory: %w", err)
	}

	names := make([]string, 0, len(entries))

	for _, entry := range entries {
		name := entry.Name()

		if !strings.HasSuffix(name, ".txt") {
			continue
		}

		info, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf(
				"inspect backup %q during retention: %w",
				name,
				err,
			)
		}

		if info.Mode()&os.ModeSymlink != 0 ||
			!info.Mode().IsRegular() {
			return fmt.Errorf(
				"unsafe backup entry during retention: %s",
				name,
			)
		}

		names = append(names, name)
	}

	if len(names) <= maxBackupFiles {
		return nil
	}

	sort.Strings(names)

	removeCount := len(names) - maxBackupFiles

	for _, name := range names {
		if removeCount == 0 {
			break
		}

		if name == protectedName {
			continue
		}

		if err := root.Remove(name); err != nil {
			return fmt.Errorf(
				"remove expired backup %q: %w",
				name,
				err,
			)
		}

		removeCount--
	}

	if removeCount != 0 {
		return errors.New(
			"backup retention cannot satisfy limit without removing protected backup",
		)
	}

	if err := syncDirectory(root); err != nil {
		return fmt.Errorf(
			"sync backup directory after retention: %w",
			err,
		)
	}

	return nil
}

func createTemporaryBackup(root *os.Root) (*os.File, string, error) {
	for range 10 {
		token, err := randomHex(16)
		if err != nil {
			return nil, "", err
		}

		name := ".aamm-ng-backup-" + token + ".tmp"

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
		"could not allocate a unique temporary backup file",
	)
}

func newBackupName(target alerttarget.Target) (string, error) {
	token, err := randomHex(8)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().UTC().Format(
		"20060102T150405.000000000Z",
	)

	return timestamp +
		"-" +
		target.String() +
		"-" +
		token +
		".txt", nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)

	if _, err := rand.Read(value); err != nil {
		return "", err
	}

	return hex.EncodeToString(value), nil
}

type boundedCapture struct {
	limit int
	data  []byte
}

func (capture *boundedCapture) Write(value []byte) (int, error) {
	remaining := capture.limit - len(capture.data)

	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}

		capture.data = append(
			capture.data,
			value[:remaining]...,
		)
	}

	return len(value), nil
}
