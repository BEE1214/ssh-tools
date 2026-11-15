//go:build unix

package config

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// ErrLockTimeout: another process held the lock for the whole wait.
var ErrLockTimeout = errors.New("timed out waiting for the lock")

// ChmodNoFollow sets the permission bits of the file at path without ever
// following a symlink: if path is (or has just been replaced by) a symlink
// the call fails instead of changing some other file.
func ChmodNoFollow(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(mode)
}

// lockPoll is how often LockFile retries a busy lock.
const lockPoll = 25 * time.Millisecond

// LockFile takes an exclusive advisory lock (flock) on the file at path,
// creating it with mode 0600 if needed, and returns a function that releases
// it. It waits up to timeout for another holder (ErrLockTimeout after that).
// The lock belongs to the open file, so it also excludes other goroutines of
// this process, and the kernel drops it if the process dies. The lock file is
// never removed: removing it would let two processes lock different inodes.
func LockFile(path string, timeout time.Duration) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, fmt.Errorf("%w: %s (held by another sshm for %s)", ErrLockTimeout, path, timeout)
		}
		time.Sleep(lockPoll)
	}
}
