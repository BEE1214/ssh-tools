package app

import (
	"errors"
	"fmt"
)

// ErrNotImplemented is returned by the P3/P4 entry points until their
// behavior is implemented (PLAN-p3-p4.md).
var ErrNotImplemented = errors.New("not implemented")

// ErrNotSetUp: a command that needs managed mode ran in legacy mode (R-section
// fixed error strings, I1).
var ErrNotSetUp = errors.New("sshm is not set up: run 'sshm setup' first")

// UnmanagedHostError: a write command targeted a host that is not defined in
// the managed file (R4, R8, R10). CanImport is true when the host is in the
// main file, where 'sshm import' can move it.
type UnmanagedHostError struct {
	Host      string
	File      string
	CanImport bool
}

func (e *UnmanagedHostError) Error() string {
	if e.CanImport {
		return fmt.Sprintf("host %q is defined in %s, which sshm does not manage; run 'sshm import'", e.Host, e.File)
	}
	return fmt.Sprintf("host %q is defined in %s (included), which sshm does not manage", e.Host, e.File)
}

// ManagedPath returns the path of the managed file: <dir of main>/config.d/sshm.conf.
func (a *App) ManagedPath() string { return managedPathFor(a.configPath) }

// ManagedActive reports whether sshm runs in managed mode: the managed file's
// path is among the files config.Load reached through an UNCONDITIONAL
// Include (PLAN-p3-p4.md section 1). Otherwise it is legacy mode, in which
// every command behaves as before (R1).
func (a *App) ManagedActive() (bool, error) {
	return false, ErrNotImplemented
}

// SetupHint returns the legacy-mode hint line
// `hint: run 'sshm setup' to keep sshm-managed hosts in <managed path>`, or ""
// in managed mode (R14).
func (a *App) SetupHint() string { return "hint: not implemented" }

// SetupOptions are the options of Setup.
type SetupOptions struct {
	// DryRun plans only: Actions lists what would be done, nothing is
	// written (S9).
	DryRun bool
}

// SetupResult describes what Setup did (or, with DryRun, would do).
type SetupResult struct {
	// AlreadySetUp: an unconditional Include of the managed file already
	// exists; nothing was or would be changed (S4, S5).
	AlreadySetUp bool
	// Actions lists the planned or performed steps, one per line, in the
	// wording of the CLI output (S1, S2, S6): "create <path> (0700)",
	// "create <path> (0600)", "insert Include line at line 1 of <main>".
	// Empty when AlreadySetUp.
	Actions []string
	// Notes carries non-fatal remarks, e.g. that verification was skipped
	// because ssh is missing or a loaded file has a 'Match ... exec' line (S7).
	Notes []string
}

// Setup makes the managed file reachable from the main file: it creates
// config.d/sshm.conf and inserts one Include line as line 1 of the main file
// (S1-S10). It is idempotent.
func (a *App) Setup(opts SetupOptions) (SetupResult, error) {
	return SetupResult{}, ErrNotImplemented
}
