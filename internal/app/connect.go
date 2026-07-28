package app

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Connect verifies the host exists in config, then replaces the current
// process with ssh connecting to that host.
//
// Uses syscall.Exec so ssh gets direct control of stdin/stdout/stderr/tty.
// This function only returns on error — on success the process is replaced.
func (a *App) Connect(name string) error {
	cfg, err := a.load()
	if err != nil {
		return err
	}

	idx := findHostIndex(cfg.Hosts, name)
	if idx == -1 {
		// Try fuzzy suggestion
		suggestion := suggestHost(cfg.Hosts, name)
		if suggestion != "" {
			return fmt.Errorf("host %q not found — did you mean %q?", name, suggestion)
		}
		return fmt.Errorf("host %q not found", name)
	}

	binary, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}

	argv := append([]string{"ssh"}, name)
	env := os.Environ()

	// syscall.Exec replaces the process. This never returns on success.
	if err := syscall.Exec(binary, argv, env); err != nil {
		return fmt.Errorf("exec ssh: %w", err)
	}

	return nil // unreachable
}

// suggestHost returns the name of a host that is similar to the given name,
// or empty string if no good suggestion is found.
func suggestHost(hosts []domain.Host, name string) string {
	// Simple: find a host that contains the name as substring or vice versa.
	for _, h := range hosts {
		if h.Name == name {
			continue
		}
		if len(h.Name) >= 3 && len(name) >= 3 {
			if contains(h.Name, name) || contains(name, h.Name) {
				return h.Name
			}
		}
	}
	return ""
}

func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}