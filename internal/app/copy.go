package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Copy runs rsync between local and remote paths using the ssh config
// for known hosts or the default identity key for ad-hoc user@host targets.
//
// rsyncFlags are the flags to pass to rsync (e.g. "-avzP").
// One of src or dst must contain a remote target (host:path or user@host:path).
// If the remote target is a known config host, rsync uses ssh directly
// (ssh config provides the identity). If it's an ad-hoc user@host, the
// default identity key is passed via -e "ssh -i <key>".
func (a *App) Copy(src, dst, rsyncFlags string) error {
	remote, isAdHoc := a.resolveRemote(src, dst)
	if remote == "" {
		return fmt.Errorf("neither source nor destination is a remote path — expected host:path or user@host:path")
	}

	// Gate: refuse remote targets whose host belongs to a disabled group.
	// Ad-hoc targets (not in config) are not gated.
	if cfg, err := a.load(); err == nil {
		if !isAdHoc {
			if err := a.ensureNotDisabled(cfg, hostFromPath(remote)); err != nil {
				return err
			}
		}
	}

	binary, err := exec.LookPath("rsync")
	if err != nil {
		return fmt.Errorf("rsync not found in PATH: %w", err)
	}

	argv := []string{"rsync"}
	if rsyncFlags != "" {
		argv = append(argv, strings.Fields(rsyncFlags)...)
	}

	// For ad-hoc targets (not in config), pass the default identity key.
	if isAdHoc {
		argv = append(argv, "-e", fmt.Sprintf("ssh -i %s", domain.DefaultIdentityFile))
	}

	argv = append(argv, src, dst)
	env := os.Environ()

	if err := syscall.Exec(binary, argv, env); err != nil {
		return fmt.Errorf("exec rsync: %w", err)
	}

	return nil // unreachable
}

// resolveRemote examines src and dst to find the remote target.
// Returns the remote string and a bool indicating whether it's ad-hoc
// (not in ssh config). Returns ("", false) if no remote path is found.
func (a *App) resolveRemote(src, dst string) (string, bool) {
	for _, path := range []string{src, dst} {
		if isRemotePath(path) {
			hostPart := hostFromPath(path)
			// Check if this host is in the config.
			cfg, err := a.load()
			if err != nil {
				// Can't load config — treat as ad-hoc if it has user@host.
				return path, strings.Contains(hostPart, "@")
			}
			idx := findHostIndex(cfg.Hosts, hostPart)
			if idx != -1 {
				return path, false
			}
			return path, strings.Contains(hostPart, "@")
		}
	}
	return "", false
}

// isRemotePath returns true if the path contains a colon separating
// a remote host from a path (e.g. "host:/path", "user@host:/path").
// A Windows drive letter like "C:" is not treated as remote.
func isRemotePath(path string) bool {
	idx := strings.Index(path, ":")
	if idx <= 0 {
		return false
	}
	// Exclude Windows drive letters (single char before colon).
	if idx == 1 {
		return false
	}
	return true
}

// hostFromPath extracts the host part from a remote path like
// "user@host:/path" or "host:/path" — returns "user@host" or "host".
func hostFromPath(path string) string {
	idx := strings.Index(path, ":")
	if idx < 0 {
		return path
	}
	return path[:idx]
}