package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	remote, isAdHoc, err := a.resolveRemote(src, dst)
	if err != nil {
		return err
	}
	if remote == "" {
		return fmt.Errorf("neither source nor destination is a remote path — expected host:path or user@host:path")
	}
	// The remote goes on the rsync command line as a plain argument, and
	// rsync hands its host on to ssh as one: neither may start with "-".
	for _, p := range []string{src, dst} {
		if !isRemotePath(p) {
			continue
		}
		if err := checkRemoteArg(p); err != nil {
			return err
		}
	}

	// Gate: refuse remote targets whose host belongs to a disabled group.
	// Ad-hoc targets (not in config) are not gated. A config that cannot be
	// loaded is an error — the gate fails closed.
	if !isAdHoc {
		l, err := a.loadAll()
		if err != nil {
			return err
		}
		if err := a.ensureHostNotDisabled(l.Hosts, hostFromPath(remote)); err != nil {
			return err
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

	if err := execReplace(binary, argv, env); err != nil {
		return fmt.Errorf("exec rsync: %w", err)
	}

	return nil // unreachable
}

// resolveRemote examines src and dst to find the remote target.
// Returns the remote string and a bool indicating whether it's ad-hoc
// (not in ssh config). Returns ("", false, nil) if no remote path is found.
// A config that cannot be loaded is an error (never silently ad-hoc).
func (a *App) resolveRemote(src, dst string) (string, bool, error) {
	for _, path := range []string{src, dst} {
		if isRemotePath(path) {
			hostPart := hostFromPath(path)
			// Check if this host is in the config.
			l, err := a.loadAll()
			if err != nil {
				return "", false, err
			}
			idx := findHostIndex(l.Hosts, hostPart)
			if idx != -1 {
				return path, false, nil
			}
			return path, strings.Contains(hostPart, "@"), nil
		}
	}
	return "", false, nil
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

// checkRemoteArg refuses a remote path ("host:path", "user@host:path") that
// would be read as an option. Two places read it:
//   - rsync reads the whole argument: "-e sh:x" is an rsync option;
//   - rsync splits "user@host" and starts `ssh -l user host ...`, so the HOST
//     part alone reaches ssh as an argument: "user@-oProxyCommand=x:path"
//     would run a command. rsync takes the host after the LAST "@" and
//     strips the brackets of "[host]" (the IPv6 form), so both are stripped
//     here before the check.
func checkRemoteArg(path string) error {
	spec := hostFromPath(path)
	if err := checkHostArg(spec); err != nil {
		return err
	}
	return checkHostArg(remoteHostOnly(spec))
}

// remoteHostOnly returns the host of a "user@host" / "user@[host]" / "host"
// spec as rsync passes it to ssh: without the user and without a leading "[".
func remoteHostOnly(spec string) string {
	if i := strings.LastIndex(spec, "@"); i >= 0 {
		spec = spec[i+1:]
	}
	return strings.TrimPrefix(spec, "[")
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
