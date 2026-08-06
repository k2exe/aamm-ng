package alertstore

import (
	"fmt"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

type DeleteResult struct {
	BackupName string
}

func (s *Store) Delete(
	target alerttarget.Target,
) (DeleteResult, error) {
	if target.String() == "" || target.Filename() == "" {
		return DeleteResult{}, ErrInvalidTarget
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.alertRoot == nil || s.backupRoot == nil {
		return DeleteResult{}, ErrClosed
	}

	snapshot, backupName, err := backupAlert(
		s.alertRoot,
		s.backupRoot,
		target,
		false,
	)
	if err != nil {
		return DeleteResult{}, err
	}

	if err := verifySourceUnchanged(
		s.alertRoot,
		target,
		snapshot,
	); err != nil {
		return DeleteResult{}, fmt.Errorf(
			"delete alert %q after backup %q: %w",
			target.String(),
			backupName,
			err,
		)
	}

	if err := s.alertRoot.Remove(target.Filename()); err != nil {
		return DeleteResult{}, fmt.Errorf(
			"delete alert %q after backup %q: %w",
			target.String(),
			backupName,
			err,
		)
	}

	if err := syncDirectory(s.alertRoot); err != nil {
		return DeleteResult{}, fmt.Errorf(
			"sync alert directory after deleting %q; backup %q: %w",
			target.String(),
			backupName,
			err,
		)
	}

	return DeleteResult{
		BackupName: backupName,
	}, nil
}
