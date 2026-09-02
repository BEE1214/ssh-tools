package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Backup copies the config file to a timestamped .bak file in the same directory.
// Returns the path to the backup file.
func Backup(path string) (string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read config: %w", err)
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	stamp := time.Now().Format("20060102-150405")
	bakPath := filepath.Join(dir, base+".bak."+stamp)

	if err := os.WriteFile(bakPath, src, 0o600); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}

	return bakPath, nil
}
