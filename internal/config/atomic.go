package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to path atomically:
// 1. Write to a temp file in the same directory.
//  2. fsync the temp file.
//  3. rename temp over the target.
//
// This prevents corruption if the process is killed mid-write.
// The temp file is created with 0600 permissions.
func AtomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".config.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up temp file on any error path.
	defer func() {
		if err != nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Preserve original file permissions if it exists.
	info, err := os.Stat(path)
	if err == nil {
		if err := os.Chmod(tmpPath, info.Mode()); err != nil {
			return fmt.Errorf("chmod temp file: %w", err)
		}
	} else if os.IsNotExist(err) {
		if err := os.Chmod(tmpPath, 0o600); err != nil {
			return fmt.Errorf("chmod temp file: %w", err)
		}
	} else {
		return fmt.Errorf("stat config: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp to config: %w", err)
	}

	return nil
}
