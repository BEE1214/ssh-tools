package app

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// AddForward validates and appends forward specs to a host's config block.
func (a *App) AddForward(host string, kind domain.ForwardKind, specs []string) error {
	v, err := a.gate()
	if err != nil {
		return err
	}
	return a.addForwardManaged(v, host, kind, specs)
}

// ListForwards returns a host's own config block (not merged with
// inherited Host * forwards), for reading its saved forward entries.
func (a *App) ListForwards(host string) (domain.Host, error) {
	l, err := a.loadAll()
	if err != nil {
		return domain.Host{}, err
	}

	idx := findHostIndex(l.Hosts, host)
	if idx == -1 {
		return domain.Host{}, fmt.Errorf("host %q not found", host)
	}

	return l.Hosts[idx], nil
}

// ClearForwards removes all forward entries (local, remote, and dynamic)
// from a host's config block.
func (a *App) ClearForwards(host string) error {
	v, err := a.gate()
	if err != nil {
		return err
	}
	return a.clearForwardsManaged(v, host)
}

// RunForward replaces the current process with ssh -N plus one -L/-R/-D
// flag per spec, connecting to host. Specs are passed to ssh verbatim (ssh
// accepts the same listenPort:targetHost:targetPort syntax used on the
// sshm CLI). If save is true, the specs are persisted to the host's config
// block first.
//
// Uses syscall.Exec so ssh gets direct control of the process. This
// function only returns on error — on success the process is replaced.
func (a *App) RunForward(host string, kind domain.ForwardKind, specs []string, save bool) error {
	return a.RunForwardNotify(host, kind, specs, save, nil)
}

// RunForwardNotify is RunForward with a callback: afterSave (may be nil) is
// called once the specs are persisted (save is true) and before ssh replaces
// the process, which is the only point where a caller can still say anything
// after a successful --save.
func (a *App) RunForwardNotify(host string, kind domain.ForwardKind, specs []string, save bool, afterSave func()) error {
	// --save writes the host's block, so the gate applies up front, before
	// anything else and before anything is exec'd (P7 G3).
	var v *managedView
	if save {
		var err error
		if v, err = a.gate(); err != nil {
			return err
		}
	}
	// The host goes on the ssh command line as a plain argument (see
	// checkHostArg). Checked before anything is saved.
	if err := checkHostArg(host); err != nil {
		return err
	}
	// The write guard of the host, also before anything is exec'd. Without
	// --save an included host is fine.
	if save {
		if err := v.unmanaged(host); err != nil {
			return err
		}
	}
	l, err := a.loadAll()
	if err != nil {
		return err
	}

	if err := a.ensureHostNotDisabled(l.Hosts, host); err != nil {
		return err
	}

	if findHostIndex(l.Hosts, host) == -1 {
		return fmt.Errorf("host %q not found", host)
	}

	for _, spec := range specs {
		if _, err := domain.ParseForwardSpec(kind, spec); err != nil {
			return err
		}
	}

	if save {
		if err := a.AddForward(host, kind, specs); err != nil {
			return err
		}
		if afterSave != nil {
			afterSave()
		}
	}

	binary, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}

	argv := []string{"ssh", "-N"}
	for _, spec := range specs {
		argv = append(argv, kind.Flag(), spec)
	}
	argv = append(argv, host)
	env := os.Environ()

	// syscall.Exec replaces the process. This never returns on success.
	if err := execReplace(binary, argv, env); err != nil {
		return fmt.Errorf("exec ssh: %w", err)
	}

	return nil // unreachable
}
