//go:build !unix

package config

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ChmodNoFollow sets the permission bits of the file at path and refuses a
// symlink (checked with Lstat first: there is no O_NOFOLLOW here).
func ChmodNoFollow(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("chmod %s: is a symlink", path)
	}
	return os.Chmod(path, mode)
}

// ErrLockTimeout: another process held the lock for the whole wait.
var ErrLockTimeout = errors.New("timed out waiting for the lock")

// LockFile is a no-op on platforms without flock(2): sshm targets OpenSSH on
// unix. Saves there are not protected against a concurrent sshm.
func LockFile(path string, timeout time.Duration) (unlock func(), err error) {
	return func() {}, nil
}
