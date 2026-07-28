package config

import (
	"os"
	"path/filepath"
)

// FindConfig returns the path to the SSH config file.
// It checks $SSH_AUTH_CONFIG first, then falls back to ~/.ssh/config.
func FindConfig() (string, error) {
	if p := os.Getenv("SSH_AUTH_CONFIG"); p != "" {
		return p, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".ssh", "config"), nil
}