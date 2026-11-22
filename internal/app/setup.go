package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

// ErrNotImplemented is returned by entry points whose behavior is not
// implemented (PLAN-p3-p4.md).
var ErrNotImplemented = errors.New("not implemented")

// ErrNotSetUp: a command that writes an ssh config ran on a config whose main
// file has no unconditional Include of the managed file (P7 G1), or whose main
// file does not exist (G4).
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

// MultiPatternError: a write was addressed by a name that is only one of
// several patterns of a Host line (P7 M1), or by the whole line text (M2). Host
// is the Name of the block, i.e. the line's argument text with comment and
// quotes stripped ("db-1 db-2"); File and Line say where the line is.
type MultiPatternError struct {
	Host string
	File string
	Line int
}

func (e *MultiPatternError) Error() string {
	return fmt.Sprintf("%q in %s has several patterns, which sshm cannot edit", "Host "+e.Host, e.File)
}

// ManagedPath returns the path of the managed file: <dir of main>/config.d/sshm.conf.
func (a *App) ManagedPath() string { return managedPathFor(a.configPath) }

// ManagedActive reports whether sshm runs in managed mode: the managed file's
// path is among the files config.Load reached through an UNCONDITIONAL
// Include (PLAN-p3-p4.md section 1), i.e. the config is set up and the write
// commands work. Otherwise the write commands return ErrNotSetUp.
func (a *App) ManagedActive() (bool, error) {
	v, err := a.activeView()
	return v != nil, err
}

// InitFresh is the fresh-machine entry of 'sshm init' (P7 I1-I4): when the main
// file does NOT exist it performs exactly the actions of Setup (directories,
// an empty managed file, the main file holding the Include line, verified like
// Setup), writes NO Host * block and returns the Setup result with fresh true.
// When the main file exists it changes nothing and returns fresh false; the
// caller then goes on with InitDefaultsReport (which returns ErrNotSetUp for a
// config that is not set up, G1). A failure leaves the previous state or a
// complete set-up state (I4).
func (a *App) InitFresh() (res SetupResult, fresh bool, err error) {
	target, err := config.WriteTarget(a.configPath)
	if err != nil {
		return SetupResult{}, false, err
	}
	if _, exists, err := readState(target); err != nil {
		return SetupResult{}, false, fmt.Errorf("read %s: %w", a.configPath, err)
	} else if exists {
		return SetupResult{}, false, nil
	}
	res, err = a.Setup(SetupOptions{})
	if err != nil {
		return SetupResult{}, false, err
	}
	return res, true, nil
}

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

// managedHeader is the content of a new managed file (S1).
const managedHeader = "# Managed by sshm. Hosts in this file are edited by sshm.\n# Lines you add by hand are kept.\n"

// includeState says how the main file reaches the managed file.
type includeState int

const (
	includeNone includeState = iota
	includeUnconditional
	includeConditional
)

// managedIncludeState decides from the loaded files and their Include lines
// whether ssh reads the managed file (S5). A loaded managed file answers it
// directly; for a file that does not exist yet the Include lines are looked at
// (a conditional Include is an error even then, 5.2). where names the
// offending line for includeConditional.
func managedIncludeState(l *config.Loaded, managed string) (state includeState, where string) {
	if f, ok := l.Lookup(managed); ok {
		if f.Conditional {
			return includeConditional, fmt.Sprintf("%s line %d", f.IncludedFrom, f.IncludeLine)
		}
		return includeUnconditional, ""
	}
	state = includeNone
	for _, f := range l.Files {
		for _, inc := range f.Cfg.Includes {
			for _, pat := range inc.Patterns {
				p, ok := config.IncludeTarget(pat)
				if !ok || !samePath(p, managed) {
					continue
				}
				if inc.Conditional || f.Conditional {
					return includeConditional, fmt.Sprintf("%s line %d", f.Path, inc.Line)
				}
				state = includeUnconditional
			}
		}
	}
	return state, ""
}

// samePath compares two paths that may not exist: cleaned, and with the
// symlinks of their directories resolved.
func samePath(a, b string) bool {
	norm := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		p = filepath.Clean(p)
		if dir, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			p = filepath.Join(dir, filepath.Base(p))
		}
		return p
	}
	return norm(a) == norm(b)
}

// includeLine is the Include line setup inserts (S3): the "~/.ssh" spelling
// iff the main file is <passwd home>/.ssh/config, else the absolute path.
func (a *App) includeLine() string {
	path := a.ManagedPath()
	if abs, err := filepath.Abs(path); err == nil {
		path = abs // ssh resolves a relative Include against ~/.ssh, not the cwd
	}
	if home := config.HomeDir(); home != "" && samePath(a.configPath, filepath.Join(home, ".ssh", "config")) {
		path = "~/.ssh/config.d/sshm.conf"
	}
	if strings.ContainsAny(path, " \t#") {
		path = `"` + path + `"`
	}
	return "Include " + path
}

// missingDirs lists the directories from the topmost missing one down to dir.
// An existing non-directory on the way is an error.
func missingDirs(dir string) ([]string, error) {
	var missing []string
	for p := dir; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		if err == nil {
			if !fi.IsDir() {
				return nil, fmt.Errorf("cannot set up: %s exists and is not a directory", p)
			}
			break
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot set up: %w", err)
		}
		missing = append([]string{p}, missing...)
		if filepath.Dir(p) == p {
			break
		}
	}
	return missing, nil
}

// verifySkipReason says why ssh -G cannot be used to verify a change ("" when
// it can): ssh missing, or a loaded file (or the managed content about to be
// included) has a Match line with an exec criterion, which ssh -G would run.
func verifySkipReason(l *config.Loaded, extra *config.Doc, extraPath string) string {
	if _, err := exec.LookPath("ssh"); err != nil {
		return "ssh not found in PATH"
	}
	if f := execMatchFile(l, extra, extraPath); f != "" {
		return fmt.Sprintf("%s has a 'Match ... exec' line, which ssh -G would run", f)
	}
	return ""
}

// setupPlan is what Setup would do.
type setupPlan struct {
	dirs          []string
	createManaged bool
	createMain    bool
	insertInclude bool
	include       string
}

func (p setupPlan) actions(main, managed string) []string {
	var out []string
	for _, d := range p.dirs {
		out = append(out, fmt.Sprintf("create %s (0700)", d))
	}
	if p.createManaged {
		out = append(out, fmt.Sprintf("create %s (0600)", managed))
	}
	switch {
	case p.createMain:
		out = append(out, fmt.Sprintf("create %s (0600) with Include line", main))
	case p.insertInclude:
		out = append(out, fmt.Sprintf("insert Include line at line 1 of %s", main))
	}
	return out
}

// Setup makes the managed file reachable from the main file: it creates
// config.d/sshm.conf and inserts one Include line as line 1 of the main file
// (S1-S10). It is idempotent.
func (a *App) Setup(opts SetupOptions) (SetupResult, error) {
	main, managed := a.configPath, a.ManagedPath()
	mainTarget, err := config.WriteTarget(main)
	if err != nil {
		return SetupResult{}, err
	}
	raw, mainExists, err := readState(mainTarget)
	if err != nil {
		return SetupResult{}, fmt.Errorf("read %s: %w", main, err)
	}

	var l *config.Loaded
	state := includeNone
	if mainExists {
		if l, err = a.loadAll(); err != nil {
			return SetupResult{}, err
		}
		if err := trustLoaded(l); err != nil {
			return SetupResult{}, fmt.Errorf("not setting up: %w", err)
		}
		var where string
		if state, where = managedIncludeState(l, managed); state == includeConditional {
			return SetupResult{}, fmt.Errorf("the Include of %s at %s is below a Host or Match line, so ssh applies it only inside that block; move it above the first Host/Match line, then run 'sshm setup' again",
				managed, where)
		}
	}

	managedRaw, managedExists, err := readState(managed)
	if err != nil {
		return SetupResult{}, fmt.Errorf("read %s: %w", managed, err)
	}
	if state == includeUnconditional && managedExists {
		return SetupResult{AlreadySetUp: true}, nil
	}

	plan := setupPlan{include: a.includeLine(), createManaged: !managedExists}
	if !managedExists {
		if plan.dirs, err = missingDirs(filepath.Dir(managed)); err != nil {
			return SetupResult{}, err
		}
	}
	if state != includeUnconditional {
		plan.createMain = !mainExists
		plan.insertInclude = mainExists
	}
	res := SetupResult{Actions: plan.actions(main, managed)}

	// Verification: ssh -G of every host before and after, unless it cannot be
	// trusted or run (S7). The managed content that will be included counts,
	// since ssh -G would run its Match exec lines.
	skip := ""
	if l != nil {
		skip = verifySkipReason(l, config.ParseDoc(managedRaw), managed)
	} else if _, lerr := exec.LookPath("ssh"); lerr != nil {
		skip = "ssh not found in PATH"
	}
	if skip != "" {
		res.Notes = append(res.Notes, "verification skipped: "+skip)
	}
	if opts.DryRun {
		return res, nil
	}

	var names []string
	var before map[string]string
	if skip == "" && l != nil {
		if names, err = probeNames(l, &config.Doc{}, verifyPlan{}); err != nil {
			return SetupResult{}, fmt.Errorf("not setting up: %w", err)
		}
		if before, err = a.resolveAll(names); err != nil {
			return SetupResult{}, fmt.Errorf("not setting up: the current ssh configuration is already broken: %w%s", err, a.backupHint(main))
		}
	}

	if err := a.applySetup(plan, raw, mainExists, mainTarget, skip == "", names, before); err != nil {
		return SetupResult{}, err
	}
	return res, nil
}

// applySetup performs plan under the lock of the main file and undoes it all
// when the result does not verify.
func (a *App) applySetup(plan setupPlan, raw []byte, mainExists bool, mainTarget string, verify bool, names []string, before map[string]string) (err error) {
	main, managed := a.configPath, a.ManagedPath()

	// From the first write to the end of the verification a signal undoes the
	// setup like a failed verification (interrupt.go). Registered first, so the
	// handler is still installed while the undo list runs.
	w := a.openInterruptWindow()
	defer func() { a.closeInterruptWindow(w, err) }()

	// Undo list, run in reverse on failure.
	var undo []func() error
	defer func() {
		if err == nil {
			return
		}
		var rerr error
		for i := len(undo) - 1; i >= 0; i-- {
			if uerr := undo[i](); uerr != nil {
				err = fmt.Errorf("%w (AND the rollback failed: %v)", err, uerr)
				rerr = errors.Join(rerr, uerr)
			}
		}
		if w.fired() {
			err = a.interrupted(w, main, rerr)
		}
	}()

	for _, d := range plan.dirs {
		if err := os.Mkdir(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
		dir := d
		undo = append(undo, func() error {
			os.Remove(filepath.Join(dir, managedLockName))
			return os.Remove(dir)
		})
		if err := os.Chmod(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}

	lock, err := managedLockPath(main)
	if err != nil {
		return fmt.Errorf("not writing %s: %w", main, err)
	}
	unlock, err := config.LockFile(lock, managedLockTimeout)
	if err != nil {
		return fmt.Errorf("not writing %s: %w", main, err)
	}
	defer unlock()

	// Lost-update check: the main file is still what the plan was made from.
	cur, curExists, err := readState(mainTarget)
	if err != nil {
		return fmt.Errorf("read %s: %w", main, err)
	}
	if curExists != mainExists || !bytes.Equal(cur, raw) {
		return fmt.Errorf("not writing %s: %w", main, ErrConflict)
	}

	if plan.createManaged {
		f, err := os.OpenFile(managed, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", managed, err)
		}
		undo = append(undo, func() error { return os.Remove(managed) })
		_, werr := f.WriteString(managedHeader)
		if werr == nil {
			werr = f.Sync()
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.Chmod(managed, 0o600)
		}
		if werr != nil {
			return fmt.Errorf("create %s: %w", managed, werr)
		}
	}

	if plan.createMain || plan.insertInclude {
		d := config.ParseDoc(raw)
		if err := d.InsertLine(0, plan.include); err != nil {
			return err
		}
		data := d.RawBytes()
		if mainExists {
			if _, err := config.BackupTo(mainTarget, a.managedBackupDir()); err != nil {
				return fmt.Errorf("backup %s: %w", main, err)
			}
		}
		if err := config.AtomicWrite(main, data); err != nil {
			return fmt.Errorf("write %s: %w", main, err)
		}
		undo = append(undo, func() error { return restoreFile(kindMain, main, data, raw, mainExists, 0) })
	}

	if w.fired() {
		return ErrInterrupted
	}

	// The result must be what ssh sees: managed file reached unconditionally.
	l2, err := a.loadAll()
	if err == nil {
		err = trustLoaded(l2)
	}
	if err == nil {
		err = managedIncluded(l2, managed)
	}
	if err != nil {
		return fmt.Errorf("setup undone: %w", err)
	}
	if !verify {
		if w.fired() {
			return ErrInterrupted
		}
		return nil
	}
	if before == nil {
		// A main file that did not exist: nothing to compare, but ssh must parse it.
		_, err = a.resolveAll([]string{probeSentinel})
	} else {
		var after map[string]string
		if after, err = a.resolveAll(names); err == nil {
			err = comparePlan(before, after, nil, verifyPlan{})
		}
	}
	if err == nil && w.fired() {
		err = ErrInterrupted
	}
	if err != nil {
		return fmt.Errorf("setup undone, files restored: %w", err)
	}
	return nil
}

// restoreFile puts orig back into path after a write of wrote (existed false:
// removes the file). It leaves a file alone that is no longer what the failed
// operation wrote (somebody else changed it since). mode is the mode of the
// managed file to restore (ignored for kindMain, whose mode never changed); a
// mode ssh refuses (group/world-writable) is replaced by 0600.
func restoreFile(kind docKind, path string, wrote, orig []byte, existed bool, mode os.FileMode) error {
	target, err := config.WriteTarget(path)
	if err != nil {
		return err
	}
	cur, curExists, err := readState(target)
	if err != nil {
		return err
	}
	if existed && curExists && bytes.Equal(cur, orig) {
		return nil // the write never happened (or already is undone)
	}
	if !curExists || !bytes.Equal(cur, wrote) {
		return fmt.Errorf("%s was changed by someone else meanwhile, so it was not restored: %w", path, ErrNotRolledBack)
	}
	if !existed {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if mode&0o022 != 0 || mode == 0 {
		mode = 0o600
	}
	return writeDoc(kind, path, orig, mode)
}
