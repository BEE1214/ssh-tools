package app

import (
	"fmt"
	"sync"

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
	// win is the interrupt handler of the verified saves that are running, nil
	// when none is (interrupt.go).
	winMu sync.Mutex
	win   *interruptWindow
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

// findHostIndex returns the index of the first host with the given name, or -1.
func findHostIndex(hosts []domain.Host, name string) int {
	for i, h := range hosts {
		if h.Name == name {
			return i
		}
	}
	return -1
}

// loadAll reads the main config file and every file reachable from it through
// Include.
func (a *App) loadAll() (*config.Loaded, error) {
	return config.Load(a.configPath)
}

// ensureInMainLoaded refuses a host that is defined only in an included file
// (the refusal text of a config that is not set up, where sshm cannot edit it).
// A name that is also defined in the main file passes. Unknown names pass too;
// callers report "not found" themselves.
func ensureInMainLoaded(l *config.Loaded, name string) error {
	other := ""
	for _, h := range l.Hosts {
		if h.Name != name {
			continue
		}
		if h.SourceFile == l.MainPath() {
			return nil
		}
		if other == "" {
			other = h.SourceFile
		}
	}
	if other != "" {
		return fmt.Errorf("host %q is defined in %s (included), which sshm cannot edit yet", name, other)
	}
	return nil
}
