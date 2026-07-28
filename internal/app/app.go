package app

import (
	"fmt"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// App is the orchestration layer. It holds the config path and provides
// methods that combine config I/O with domain logic.
//
// App is stateless between operations — each method reads the config file
// fresh from disk. This prevents stale cache problems if the file is
// edited externally (e.g. hand-edited or DevPod updates it).
type App struct {
	configPath string
}

// NewApp creates an App using the default config location.
func NewApp() (*App, error) {
	path, err := config.FindConfig()
	if err != nil {
		return nil, fmt.Errorf("find ssh config: %w", err)
	}
	return &App{configPath: path}, nil
}

// NewAppWithPath creates an App with an explicit config path (for testing).
func NewAppWithPath(path string) *App {
	return &App{configPath: path}
}

// ConfigPath returns the path to the SSH config file.
func (a *App) ConfigPath() string { return a.configPath }

// load reads and parses the config file.
func (a *App) load() (*config.ConfigFile, error) {
	raw, err := configReadFile(a.configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// save backs up the current file, then atomically writes the new content.
func (a *App) save(cfg *config.ConfigFile) error {
	if _, err := config.Backup(a.configPath); err != nil {
		return fmt.Errorf("backup config: %w", err)
	}
	data, err := config.Write(cfg)
	if err != nil {
		return fmt.Errorf("serialize config: %w", err)
	}
	if err := config.AtomicWrite(a.configPath, data); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// findHostIndex returns the index of the first host with the given name, or -1.
func findHostIndex(hosts []domain.Host, name string) int {
	for i, h := range hosts {
		if h.Name == name {
			return i
		}
	}
	return -1
}