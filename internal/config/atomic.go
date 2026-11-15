package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to path atomically:
//  1. Write to a temp file in the same directory.
//  2. fsync the temp file.
//  3. rename temp over the target.
//
// This prevents corruption if the process is killed mid-write. If path is a
// symlink (e.g. a dotfiles-managed ~/.ssh/config) the data is written to the
// file the link points to and the link itself is left in place. The target's
// permissions are preserved when it exists; a new file gets 0600.
func AtomicWrite(path string, data []byte) error {
	return atomicWrite(path, data, 0o600, true)
}

// AtomicWriteMode is AtomicWrite with the file mode FORCED to mode, whatever
// the previous mode of the target was (a group-writable file ends up 0600).
// Symlinks are written through, as in AtomicWrite.
func AtomicWriteMode(path string, data []byte, mode os.FileMode) error {
	return atomicWrite(path, data, mode, false)
}

// atomicWrite implements both variants. With preserve, an existing target
// keeps its mode and mode only applies to a new file.
func atomicWrite(path string, data []byte, mode os.FileMode, preserve bool) (err error) {
	target, err := resolveLink(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(target)

	if preserve {
		if info, serr := os.Stat(target); serr == nil {
			mode = info.Mode().Perm()
		} else if !os.IsNotExist(serr) {
			return fmt.Errorf("stat config: %w", serr)
		}
	}

	tmp, err := os.CreateTemp(dir, ".config.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up the temp file on any error path.
	defer func() {
		if err != nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmpPath, target); err != nil {
		return fmt.Errorf("rename temp to config: %w", err)
	}
	// Make the rename durable; best effort (not every filesystem supports it).
	if d, derr := os.Open(dir); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// resolveLink follows path through any chain of symlinks and returns the path
// of the file a write must replace. A dangling link resolves to its (not yet
// existing) target; a plain or missing path is returned unchanged.
func resolveLink(path string) (string, error) {
	for i := 0; i < 32; i++ {
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return path, nil
			}
			return "", fmt.Errorf("stat config: %w", err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
		dest, err := os.Readlink(path)
		if err != nil {
			return "", fmt.Errorf("read symlink %s: %w", path, err)
		}
		if !filepath.IsAbs(dest) {
			dest = filepath.Join(filepath.Dir(path), dest)
		}
		path = dest
	}
	return "", fmt.Errorf("too many levels of symbolic links: %s", path)
}

// WriteTarget returns the file an atomic write to path would replace (path
// itself unless it is a symlink).
func WriteTarget(path string) (string, error) { return resolveLink(path) }
