package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

// verifyPlan says what a managed-file save is allowed to change and what it
// must achieve, as seen by `ssh -G`.
//
// Every probed name not in changed must resolve identically before and after.
// A host in changed may differ only in the option lines listed in keys[host]
// (lower-case option names exactly as `ssh -G` prints them, e.g. "user",
// "identityfile"). An option that ssh derives from an edited one through
// tokens ("ControlPath ~/.ssh/cm-%C" after a User edit) may differ too, but
// only to the exact value ssh predicts for the expected new values (see
// tokenDerived, predictDerived). A changed host with no keys entry may differ
// in any line (add / delete / duplicate / disable).
//
// expect[host][key] lists values that MUST be in effect for host after the
// save (set / add-value edits), exactly as ssh renders them: ssh is asked
// before the write how it prints each value (predictExpect) and the line
// after the write must be that. A write that ssh accepts but that changes
// nothing, because an earlier block or file sets the option first, is rolled
// back, and so is one that puts another value there than the plan says. See
// checkExpect for the exact rule.
//
// probe lists extra names to resolve. Names that only match a pattern block
// ("Host web-*", "Host *") appear on no Host line, so nothing would notice an
// edit to that block; the caller passes names that hit the pattern. A probe
// name (and the built-in sentinel) that is not in changed itself may change
// the way the pattern entries of changed may: the union of their keys.
type verifyPlan struct {
	changed map[string]bool
	keys    map[string]map[string]bool
	expect  map[string]map[string][]string
	probe   []string
}

// editPlan is the plan for edits that have no expected value (unset, remove
// a list value) of the options keys (ssh -G names, any case) of one host.
func editPlan(host string, keys ...string) verifyPlan {
	k := map[string]bool{}
	for _, key := range keys {
		k[strings.ToLower(key)] = true
	}
	return verifyPlan{changed: map[string]bool{host: true}, keys: map[string]map[string]bool{host: k}}
}

// setPlan is the plan for Doc.SetOption edits of one host: kv is a list of
// option, value pairs. Each option may change and each value must be in
// effect afterwards.
func setPlan(host string, kv ...string) verifyPlan {
	v := editPlan(host)
	v.expect = map[string]map[string][]string{host: {}}
	for i := 0; i+1 < len(kv); i += 2 {
		key := strings.ToLower(kv[i])
		v.keys[host][key] = true
		v.expect[host][key] = append(v.expect[host][key], kv[i+1])
	}
	return v
}

// addValuePlan is the plan for Doc.AddOptionValue: host must list value for
// the list option key afterwards.
func addValuePlan(host, key, value string) verifyPlan {
	return setPlan(host, key, value)
}

// anyChangePlan is the plan for operations that may change everything about
// the named hosts (add, delete, duplicate, disable, enable).
func anyChangePlan(hosts ...string) verifyPlan {
	c := map[string]bool{}
	for _, h := range hosts {
		c[h] = true
	}
	return verifyPlan{changed: c}
}

// withProbe returns v with extra names to resolve (see verifyPlan.probe).
func (v verifyPlan) withProbe(names ...string) verifyPlan {
	v.probe = append(slices.Clone(v.probe), names...)
	return v
}

// allowed reports whether name may resolve differently after the save and in
// which keys (nil: in any line).
func (v verifyPlan) allowed(name string) (may bool, keys map[string]bool) {
	if v.changed[name] {
		return true, v.keys[name]
	}
	if name != probeSentinel && !slices.Contains(v.probe, name) {
		return false, nil
	}
	// The sentinel and extra probe names stand for "whatever a pattern block
	// matches": they inherit what the plan allows for its pattern entries.
	union := map[string]bool{}
	for p := range v.changed {
		if !strings.ContainsAny(p, "*?!") {
			continue
		}
		may = true
		if v.keys[p] == nil {
			return true, nil
		}
		for k := range v.keys[p] {
			union[k] = true
		}
	}
	return may, union
}

// ErrConflict: the managed file on disk is not the content the Doc was parsed
// from, so somebody else (another sshm, an editor) changed it in between.
// Nothing is written; the caller must read the file again and redo the edit.
// Also returned when the file was replaced by somebody else right after this
// save wrote it (during verification): their content stays, redo the edit.
var ErrConflict = errors.New("changed on disk since it was read; re-read and retry")

const (
	// managedLockName is the lock file, in the directory of the file that is
	// really written (managedLockPath). A dot file: neither ssh's glob nor
	// config.ExpandInclude matches it with "*".
	managedLockName = ".sshm.lock"

	// probeSentinel is a name no config defines. It is always resolved, so
	// ssh parses the whole configuration (and reports a syntax error) even
	// when there is no concrete host name to probe, and so a change to what
	// an unknown host gets ("Host *", global options) is noticed.
	probeSentinel = "sshm-verify-sentinel.invalid"
)

// managedLockTimeout is how long a save waits for another sshm that is
// writing the same managed file. A variable so tests can shorten it.
var managedLockTimeout = 10 * time.Second

// managedBackupDir is where saveManagedDoc keeps its backups: next to the main
// config but outside any directory ssh might glob with Include. BackupTo
// keeps the newest config.MaxBackups per file name.
func (a *App) managedBackupDir() string {
	return filepath.Join(filepath.Dir(a.configPath), "sshm-backups")
}

// sshTimeout bounds one `ssh -G` call; -G never connects, so this is only a
// guard against a hung ssh.
const sshTimeout = 15 * time.Second

// ErrNotRolledBack: a save failed its verification, but the file was no
// longer what the save had written (somebody else changed it meanwhile), so
// it was left alone instead of being overwritten with the old content.
var ErrNotRolledBack = errors.New("changed by someone else during the save; not rolled back")

// saveManagedDoc writes d to the managed file at path with a semantic safety
// net, because a bad managed file breaks every ssh call that includes it.
// Everything below happens under an exclusive lock on .sshm.lock in the
// directory of the file that is really written (managedLockPath):
//
//  1. the file on disk must still be the bytes d was parsed from (d.Base()),
//     else ErrConflict and nothing is written; the same comparison is made
//     again right before the backup and right before the write, because the
//     probes in between take time and the lock only excludes other sshm
//     processes, not an editor. This narrows the lost-update window, it does
//     not close it: from that last comparison (unchanged) through the
//     temp-file write, chmod and fsync of AtomicWriteMode up to its rename,
//     a change another program makes to the file is overwritten unseen. The
//     rollback of step 7 has the same window between its own comparison and
//     its rename;
//  2. the loaded configuration must be what ssh sees: no Include that sshm
//     could not follow, and the managed file reachable through an Include
//     that ssh applies to every host; else nothing is written (for a file
//     that does not exist yet the second half is checked right after the
//     write and rolled back);
//  3. resolve every probe name (ssh -F <main> -G <name>) BEFORE, and ask ssh
//     what the expected values of the plan do to the options that take
//     tokens (predictDerived) and how it prints the expected values
//     themselves (predictExpect); a value ssh rejects stops the save here;
//  4. back up the file into <dir of main>/sshm-backups/ (none if it is new);
//  5. write atomically, mode forced to 0600, through a symlink if there is one;
//  6. resolve again; check v.expect and compare according to v;
//  7. on any difference or ssh error restore the previous content (or remove
//     the new file), run ssh once more and return an error that names the
//     first differing lines and says whether ssh works again. The restore
//     only happens while the file is still what step 5 wrote; otherwise it
//     is left as it is (ErrNotRolledBack). The previous mode comes back too,
//     unless it was one ssh refuses (group/world-writable): then 0600 stays.
//
// Verification is skipped, with a note, when ssh is not in PATH or a loaded
// file has a "Match ... exec" line (ssh -G would run it). If ssh already fails
// on the CURRENT configuration nothing is written.
func (a *App) saveManagedDoc(path string, d *config.Doc, v verifyPlan) (note string, err error) {
	lock, err := managedLockPath(path)
	if err != nil {
		return "", fmt.Errorf("not writing %s: %w", path, err)
	}
	unlock, err := config.LockFile(lock, managedLockTimeout)
	if err != nil {
		return "", fmt.Errorf("not writing %s: %w", path, err)
	}
	defer unlock()
	return a.saveDocLocked(kindManaged, path, d, v)
}

// docKind says which file a Doc stands for, because the two are saved with the
// same safety net but differ in the details.
type docKind int

const (
	// kindManaged: sshm.conf. Written through Doc.Bytes with mode forced to
	// 0600; ssh must reach it through an unconditional Include.
	kindManaged docKind = iota
	// kindMain: the hand-owned ssh config (init's Host * block). Written through
	// Doc.RawBytes, so no byte but the appended lines changes, with the mode of
	// the file (and symlinks) kept.
	kindMain
)

// saveMainDoc saves a raw edit of the main config file d (a Doc of the main
// file) with the verification of saveManagedDoc: lock, lost-update check,
// backup, atomic write, ssh -G before and after under the plan v, rollback.
func (a *App) saveMainDoc(d *config.Doc, v verifyPlan) (note string, err error) {
	path := a.configPath
	lock, err := managedLockPath(path)
	if err != nil {
		return "", fmt.Errorf("not writing %s: %w", path, err)
	}
	unlock, err := config.LockFile(lock, managedLockTimeout)
	if err != nil {
		return "", fmt.Errorf("not writing %s: %w", path, err)
	}
	defer unlock()
	return a.saveDocLocked(kindMain, path, d, v)
}

// docBytes is what a save of d writes.
func docBytes(kind docKind, d *config.Doc) []byte {
	if kind == kindMain {
		return d.RawBytes()
	}
	return d.Bytes()
}

// writeDoc writes data to path atomically (through a symlink). The managed
// file gets exactly mode; the main file keeps the mode it has.
func writeDoc(kind docKind, path string, data []byte, mode os.FileMode) error {
	if kind == kindMain {
		return config.AtomicWrite(path, data)
	}
	return config.AtomicWriteMode(path, data, mode)
}

// managedLockPath returns the lock file for the managed file at path. It
// lives in the directory of the file a write really replaces, with every
// symlink resolved (a symlinked sshm.conf, a symlinked config.d), so that two
// paths to one file take the same lock.
func managedLockPath(path string) (string, error) {
	target, err := config.WriteTarget(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(target)
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Join(dir, managedLockName), nil
}

// readState reads the managed file; a missing file is (nil, false, nil).
func readState(target string) (data []byte, exists bool, err error) {
	data, err = os.ReadFile(target)
	switch {
	case err == nil:
		return data, true, nil
	case os.IsNotExist(err):
		return nil, false, nil
	}
	return nil, false, err
}

func (a *App) saveDocLocked(kind docKind, path string, d *config.Doc, v verifyPlan) (note string, err error) {
	data := docBytes(kind, d)
	target, err := config.WriteTarget(path)
	if err != nil {
		return "", err
	}

	// 1. Lost-update check: a missing file counts as empty.
	orig, existed, rerr := readState(target)
	if rerr != nil {
		return "", fmt.Errorf("read %s: %w", path, rerr)
	}
	if !bytes.Equal(orig, d.Base()) {
		return "", fmt.Errorf("not writing %s: %w", path, ErrConflict)
	}
	origMode := os.FileMode(0o600)
	if existed {
		fi, serr := os.Stat(target)
		if serr != nil {
			return "", fmt.Errorf("stat %s: %w", path, serr)
		}
		origMode = fi.Mode().Perm()
	}
	// modeNote is set once a group/world-writable file was tightened to
	// 0600. That repair is never undone (ssh refuses the old mode), so every
	// error below has to mention it.
	modeNote := ""
	fail := func(err error) (string, error) {
		if modeNote != "" {
			err = fmt.Errorf("%w (%s; they stay 0600)", err, modeNote)
		}
		return "", err
	}
	// unchanged repeats check 1: the file is still exactly what was read.
	unchanged := func() error {
		cur, curExists, cerr := readState(target)
		if cerr != nil {
			return fmt.Errorf("read %s: %w", path, cerr)
		}
		if curExists != existed || !bytes.Equal(cur, orig) {
			return fmt.Errorf("not writing %s: %w", path, ErrConflict)
		}
		return nil
	}

	// 2. Is the loaded view what ssh sees?
	l, err := a.loadAll()
	if err != nil {
		return "", err
	}
	if err := trustLoaded(l); err != nil {
		return "", fmt.Errorf("not writing %s: %w", path, err)
	}
	if existed && kind == kindManaged {
		if err := managedIncluded(l, path); err != nil {
			return "", fmt.Errorf("not writing: %w", err)
		}
	}
	if !existed && kind == kindMain {
		return "", fmt.Errorf("not writing %s: the file does not exist", path)
	}

	skip := ""
	if _, lerr := exec.LookPath("ssh"); lerr != nil {
		skip = "ssh not found in PATH"
	} else if f := execMatchFile(l, d, path); f != "" {
		skip = fmt.Sprintf("%s has a 'Match ... exec' line, which ssh -G would run", f)
	}

	names, err := probeNames(l, d, v)
	if err != nil {
		return "", fmt.Errorf("not writing %s: %w", path, err)
	}

	// 3. Before.
	var before map[string]string
	var pred, rendered map[string]map[string][]string
	if skip == "" {
		before, err = a.resolveAll(names)
		if err != nil && existed {
			// A managed file that is group/world-writable makes ssh refuse the
			// whole config ("Bad owner or permissions"). Tightening it is
			// exactly what this save does anyway, so repair and retry once.
			// The repair stays even if the save does not go through: putting
			// back a mode that ssh refuses would break ssh again on purpose.
			if fixed, ferr := fixWritableModeOf(kind, target); ferr == nil && fixed != "" {
				note, modeNote = fixed, fixed
				before, err = a.resolveAll(names)
			}
		}
		if err != nil {
			return fail(fmt.Errorf("not writing %s: the current ssh configuration is already broken: %w", path, err))
		}
		// What ssh itself derives from the expected values, on the
		// configuration as it is now.
		if pred, err = a.predictDerived(names, v); err != nil {
			return fail(fmt.Errorf("not writing %s: %w", path, err))
		}
		// And how ssh itself prints every expected value.
		if rendered, err = a.predictExpect(before, pred, v); err != nil {
			return fail(fmt.Errorf("not writing %s: %w", path, err))
		}
	}

	// 1 again: the probes above took time, and the lock does not stop an
	// editor. Checked before the backup (so a conflict leaves no backup
	// behind) and once more right before the write. What stays open is the
	// time from that last unchanged() through AtomicWriteMode's temp-file
	// write, chmod and fsync to its rename.
	if err := unchanged(); err != nil {
		return fail(err)
	}

	// 4. Backup (only an existing file has anything to lose).
	var bakPath string
	if existed {
		if bakPath, err = config.BackupTo(target, a.managedBackupDir()); err != nil {
			return fail(fmt.Errorf("backup %s: %w", path, err))
		}
	}

	// 5. Write.
	if err := unchanged(); err != nil {
		return fail(err)
	}
	if err := writeDoc(kind, path, data, 0o600); err != nil {
		return fail(fmt.Errorf("write %s: %w", path, err))
	}

	// 7. (defined here, used below) Restore the content, then look at ssh
	// once more so the error says what state the user is left in.
	rollback := func(cause error) error {
		// Undo only what this save wrote. If the file is not that any more,
		// somebody else changed it during verification, and writing the old
		// content over it would destroy their edit. (Same residual window
		// as the write: a change between this comparison and the rename of
		// the restore below is overwritten.)
		cur, curExists, cerr := readState(target)
		if cerr != nil || !curExists || !bytes.Equal(cur, data) {
			was := "there was no file before this save"
			if existed {
				was = "the content from before this save is in the backup " + bakPath
			}
			return fmt.Errorf("change to %s failed (%v) and %s was left as it is now: %w; %s",
				path, cause, path, ErrNotRolledBack, was)
		}
		var rerr error
		kept := ""
		if existed {
			// Never restore a mode ssh refuses.
			mode := origMode
			if mode&0o022 != 0 {
				mode = 0o600
				kept = fmt.Sprintf("; permissions stay 0600 (they were %04o, which ssh refuses)", origMode)
			}
			rerr = writeDoc(kind, path, orig, mode)
		} else if rerr = os.Remove(target); os.IsNotExist(rerr) {
			rerr = nil
		}
		if rerr != nil {
			return fmt.Errorf("change to %s failed (%v) AND the rollback failed: %v; backup: %s",
				path, cause, rerr, bakPath)
		}
		state := ""
		if before != nil {
			state = "; " + a.sshStateAfterRestore(names, before)
		}
		return fmt.Errorf("change to %s rolled back, file restored%s%s: %w", path, kept, state, cause)
	}

	// 2 again, on what is on disk now: the new content may bring Includes of
	// its own, and a file that did not exist could not be checked before.
	l2, err := a.loadAll()
	if err == nil {
		err = trustLoaded(l2)
	}
	if err == nil {
		if kind == kindManaged {
			err = managedIncluded(l2, path)
		}
	}
	if err != nil {
		return "", rollback(err)
	}
	if skip == "" {
		if f := execMatchFile(l2, nil, ""); f != "" {
			skip = fmt.Sprintf("%s has a 'Match ... exec' line, which ssh -G would run", f)
		}
	}
	if skip != "" {
		return joinNotes(note, "verification skipped: "+skip), nil
	}

	// 6. After. The expectations first: an edit that changed nothing is
	// reported as such, not as a prediction that did not come true.
	after, verr := a.resolveAll(names)
	if verr == nil {
		verr = checkExpect(before, after, rendered, v)
	}
	if verr == nil {
		verr = comparePlan(before, after, pred, v)
	}
	if verr != nil {
		return "", rollback(verr)
	}
	// Verified, but is it still this save's content that ssh was looking at?
	// If somebody replaced the file during verification, the edit is not in
	// it any more; reporting success would be a silent lost update.
	if cur, curExists, cerr := readState(target); cerr != nil || !curExists || !bytes.Equal(cur, data) {
		return "", fmt.Errorf("%s was changed by someone else while the save was being verified, so the change may not be in it (it was left as it is now): %w",
			path, ErrConflict)
	}
	return note, nil
}

// sshStateAfterRestore re-runs the BEFORE probes after a rollback and says in
// a few words what ssh makes of the restored configuration.
func (a *App) sshStateAfterRestore(names []string, before map[string]string) string {
	now, err := a.resolveAll(names)
	switch {
	case err != nil:
		return fmt.Sprintf("ssh is now FAILING (%v)", err)
	case !maps.Equal(now, before):
		return "ssh now works but resolves differently than before the save"
	}
	return "ssh now OK"
}

func joinNotes(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// trustLoaded refuses a loaded view that is not what ssh sees: with an
// Include that sshm could not follow, ssh may read hosts nobody probes and
// may run a "Match exec" nobody saw, so no ssh -G result can be trusted (and
// ssh -G must not even be run).
func trustLoaded(l *config.Loaded) error {
	if len(l.Unfollowed) == 0 {
		return nil
	}
	more := ""
	if n := len(l.Unfollowed) - 1; n > 0 {
		more = fmt.Sprintf(" (and %d more)", n)
	}
	return fmt.Errorf("ssh may read configuration that sshm cannot follow, so a change cannot be verified: %s%s; fix or remove that Include",
		l.Unfollowed[0], more)
}

// managedIncluded checks that ssh really reads the managed file at path: it
// must be one of the loaded files (symlinks resolved on both sides) and its
// Include must not be conditional.
func managedIncluded(l *config.Loaded, path string) error {
	f, ok := l.Lookup(path)
	if !ok {
		return fmt.Errorf("ssh does not read %s: no Include reachable from %s names it; run 'sshm setup'",
			path, l.MainPath())
	}
	if f.Conditional {
		return fmt.Errorf("the Include of %s (%s line %d) is conditional: it comes after a Host or Match line that does not match every host, so ssh applies the file only inside that block; move the Include above the first Host/Match line or run 'sshm setup'",
			path, f.IncludedFrom, f.IncludeLine)
	}
	return nil
}

// fixWritableModeOf is fixWritableMode for the managed file; the hand-owned
// main file's mode is never changed.
func fixWritableModeOf(kind docKind, target string) (string, error) {
	if kind != kindManaged {
		return "", nil
	}
	return fixWritableMode(target)
}

// fixWritableMode chmods an existing group/world-writable regular file to
// 0600 and returns a note about it ("" when nothing needed fixing). There is
// no way back on purpose: ssh refuses the old mode. target must be the
// resolved managed file: a symlink is never followed (config.ChmodNoFollow).
func fixWritableMode(target string) (note string, err error) {
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 == 0 {
		return "", err
	}
	old := info.Mode().Perm()
	if err := config.ChmodNoFollow(target, 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("changed permissions of %s from %04o to 0600 (ssh refuses group/world-writable config files)", target, old), nil
}

// execMatchFile returns the first loaded file (or the new content d of the
// managed file, path; d may be nil) that contains a Match line with an exec
// criterion (config.IsMatchExecLine: `ssh -G` would run its command), or "".
func execMatchFile(l *config.Loaded, d *config.Doc, path string) string {
	if d != nil {
		for _, line := range d.Lines {
			if config.IsMatchExecLine(line) {
				return path
			}
		}
	}
	for _, f := range l.Files {
		for _, line := range f.Cfg.RawTextLines() {
			if config.IsMatchExecLine(line) {
				return f.Path
			}
		}
	}
	return ""
}

// probeable reports whether name can be handed to `ssh -G` as a host and
// means what the Host line means. Not probeable:
//   - patterns (* ? !): they are not host names;
//   - "@" (ssh splits user@host: "a@b" probes host b) and "/" ("ssh://h" is
//     read as a URI); a Host pattern with either can never match anyway;
//   - what ssh refuses with "hostname contains invalid characters": a leading
//     "-", blanks, control characters and any of ' ` " $ \ ; & < > | ( ) { } ,
//     (ssh.c valid_hostname; the comma checked with OpenSSH 10.6).
//
// Such a name is skipped, never an error: one odd Host line must not block
// every save.
func probeable(name string) bool {
	if name == "" || name[0] == '-' {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("*?!@/'`\"$\\;&<>|(){},", r) {
			return false
		}
	}
	return true
}

// probeNames lists, sorted and de-duplicated, every name to resolve: the
// sentinel, the plain names on the enabled Host lines of the loaded view AND
// of the new managed content d (so a block the plan does not declare is
// noticed too), every name in v.changed and v.probe. Unprobeable names are
// skipped. A host with an expectation must be probeable: otherwise the plan
// cannot be verified and that is an error.
func probeNames(l *config.Loaded, d *config.Doc, v verifyPlan) ([]string, error) {
	set := map[string]bool{probeSentinel: true}
	add := func(n string) {
		if probeable(n) {
			set[n] = true
		}
	}
	for _, h := range l.Hosts {
		if h.Disabled {
			continue
		}
		for _, n := range h.PatternList() {
			add(n)
		}
	}
	for _, b := range d.Blocks() {
		if b.Match || b.Disabled {
			continue
		}
		for _, n := range b.Names {
			add(n)
		}
	}
	for n := range v.changed {
		add(n)
	}
	for _, n := range v.probe {
		add(n)
	}
	for h := range v.expect {
		if !set[h] {
			return nil, fmt.Errorf("cannot verify the change: %q is not a name ssh can resolve (a pattern?); pass a concrete name that matches it", h)
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// resolveAll returns the `ssh -G` output of every name.
func (a *App) resolveAll(names []string) (map[string]string, error) {
	out := make(map[string]string, len(names))
	for _, n := range names {
		s, err := a.sshG(n)
		if err != nil {
			return nil, err
		}
		out[n] = s
	}
	return out, nil
}

// sshRun runs ssh with args and returns what it printed. A variable so tests
// can count or replace the calls; nothing else in this package starts ssh for
// verification.
var sshRun = func(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return so.Bytes(), se.Bytes(), err
}

// sshG runs `ssh -F <main config> -G -- name` and returns its output with
// the lines in ssh's own order (the order of IdentityFile and other list
// options is significant, so nothing is sorted). -G prints the resolved
// configuration and never connects.
//
// opts are "Key=value" overrides, each passed as `-o Key=value` before the
// host. ssh reads such an argument exactly like the config line "Key value"
// and BEFORE any file, so it takes precedence over the whole configuration.
func (a *App) sshG(name string, opts ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshTimeout)
	defer cancel()
	args := []string{"-F", a.configPath, "-G"}
	for _, o := range opts {
		args = append(args, "-o", o)
	}
	stdout, stderr, err := sshRun(ctx, append(args, "--", name)...)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("ssh -G %s: %s", name, msg)
	}
	return strings.TrimRight(string(stdout), "\n"), nil
}

// optionValues splits `ssh -G` output into option -> values, each list in
// output order.
func optionValues(out string) map[string][]string {
	m := map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		if l == "" {
			continue
		}
		key, val, _ := strings.Cut(l, " ")
		m[key] = append(m[key], val)
	}
	return m
}

// tokenSources are the options whose value ssh substitutes into OTHER options
// through percent tokens, and tokenDerived are the options that accept those
// tokens (ssh_config(5), TOKENS): %h is HostName, %p Port, %r User, %j
// ProxyJump, %k HostKeyAlias (HostName when unset) and %C a hash of
// %l%h%p%r%j. With "ControlPath ~/.ssh/cm-%C" in Host *, an edit of User
// therefore changes the controlpath line of `ssh -G` too.
//
// A derived option gets no free pass for that. It may take exactly ONE value
// after an edit of a source option: the one ssh itself computes for the
// expected new source values on the configuration as it was (predictDerived).
// Anything else (an added forward, a rewritten ProxyCommand, a reordered
// IdentityFile list) is an undeclared change.
//
// The table is ssh_config(5) TOKENS plus what OpenSSH 10.6 really prints:
// dynamicforward is here because -G repeats a unix-socket LocalForward on a
// dynamicforward line. TestTokenDerivedTableCoversSSH checks it against the
// installed ssh. A derived option missing from the table costs a refused
// (rolled back) edit, never an unnoticed change.
var (
	tokenSources = map[string]bool{
		"hostname": true, "user": true, "port": true, "proxyjump": true, "hostkeyalias": true,
	}
	tokenDerived = map[string]bool{
		"controlpath":          true,
		"proxycommand":         true,
		"proxyjump":            true,
		"localcommand":         true,
		"remotecommand":        true,
		"knownhostscommand":    true,
		"identityagent":        true,
		"userknownhostsfile":   true,
		"globalknownhostsfile": true,
		"identityfile":         true,
		"certificatefile":      true,
		"hostkeyalias":         true,
		"revokedhostkeys":      true,
		"localforward":         true,
		"remoteforward":        true,
		"dynamicforward":       true,
		"versionaddendum":      true,
	}
)

// sourceOverrides returns the plan's expected new values of the token source
// options of host as "key=value" arguments for `ssh -o`, in a fixed order
// (nil when the plan expects none).
func sourceOverrides(v verifyPlan, host string) []string {
	var opts []string
	for _, k := range sortedSet(tokenSources) {
		for _, val := range v.expect[host][k] {
			opts = append(opts, k+"="+val)
		}
	}
	return opts
}

// predictDerived asks ssh, BEFORE anything is written, what every probe name
// with expected token-source values will resolve to once those values are in
// effect: `ssh -F <main> -G -o user=<new> ... -- <name>`. An -o option is read
// like a config line and wins over every file, which is what the edited line
// does when the edit takes effect (when it does not, checkExpect reports
// that). The result maps name -> option -> values in ssh's order; only the
// tokenDerived options of it are used (comparePlan).
//
// A name without expected source values has no entry: for it no derived
// option may change at all. An ssh error here means ssh rejects one of the
// expected values; nothing has been written yet.
//
// Known limit: an -o option is in effect from the first line of the
// configuration, the edited line only from its own position. A "Match host"
// or "Match user" block that stands ABOVE the edited block and sets a
// derived option is therefore predicted to apply although it does not; the
// edit is then rolled back (never accepted wrongly).
func (a *App) predictDerived(names []string, v verifyPlan) (map[string]map[string][]string, error) {
	pred := map[string]map[string][]string{}
	for _, n := range names {
		opts := sourceOverrides(v, n)
		if len(opts) == 0 {
			continue
		}
		out, err := a.sshG(n, opts...)
		if err != nil {
			return nil, fmt.Errorf("ssh does not accept the new values (%s): %w", strings.Join(opts, ", "), err)
		}
		pred[n] = optionValues(out)
	}
	return pred, nil
}

// verifyError is the error of comparePlan: the text names the first differing
// lines, keys lists the ssh -G options (lower case) that differed, so callers
// can tell a token-derived option (ControlPath ... %C) from an ordinary one.
type verifyError struct {
	msg  string
	keys []string
}

func (e *verifyError) Error() string { return e.msg }

// comparePlan checks after against before under v. pred is the result of
// predictDerived (nil: nothing predicted). For every probe name:
//   - a name the plan does not allow to change must resolve identically;
//   - a changed host without a keys entry may differ in any line;
//   - otherwise an option in keys may differ; a tokenDerived option must be
//     exactly (same values, same order) what pred says for that name, or
//     unchanged when pred has no entry for the name; every other option must
//     be unchanged.
//
// The error names the first differing lines.
func comparePlan(before, after map[string]string, pred map[string]map[string][]string, v verifyPlan) error {
	names := make([]string, 0, len(before))
	for n := range before {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		may, allowed := v.allowed(n)
		if may && allowed == nil {
			continue
		}
		var p map[string][]string
		if may {
			p = pred[n]
		}
		if p == nil && before[n] == after[n] {
			continue
		}
		b, a := optionValues(before[n]), optionValues(after[n])
		keys := map[string]bool{}
		for k := range b {
			keys[k] = true
		}
		for k := range a {
			keys[k] = true
		}
		for k := range p {
			keys[k] = true
		}
		var bad, badKeys []string
		for _, k := range sortedSet(keys) {
			switch {
			case may && allowed[k]:
				// The edited option itself: checkExpect looks at it.
			case p != nil && tokenDerived[k]:
				// Exactly what ssh derives from the expected values.
				if slices.Equal(p[k], a[k]) {
					continue
				}
				badKeys = append(badKeys, k)
				if slices.Equal(b[k], a[k]) {
					bad = append(bad, fmt.Sprintf("= %s stayed [%s], but with the edited options ssh derives [%s]",
						k, strings.Join(a[k], ", "), strings.Join(p[k], ", ")))
					continue
				}
				bad = append(bad, valueDiff(k, b[k], a[k])...)
				bad = append(bad, fmt.Sprintf("  (from the edited options ssh derives %s [%s])", k, strings.Join(p[k], ", ")))
			case !slices.Equal(b[k], a[k]):
				// Ordered comparison: a reordered IdentityFile list is a change.
				badKeys = append(badKeys, k)
				bad = append(bad, valueDiff(k, b[k], a[k])...)
			}
		}
		if len(bad) == 0 {
			continue
		}
		if len(bad) > 6 {
			bad = append(bad[:6], "...")
		}
		what := "must not change"
		if may {
			what = "changed beyond the edited options"
		}
		return &verifyError{
			msg: fmt.Sprintf("verification failed: ssh -G %s %s (- before, + after):\n  %s",
				n, what, strings.Join(bad, "\n  ")),
			keys: badKeys,
		}
	}
	return nil
}

// expectOverrides returns every expected value of host as "key=value"
// arguments for `ssh -o`: keys sorted, the values of a key in plan order (nil
// when the plan expects nothing of host).
func expectOverrides(v verifyPlan, host string) []string {
	var opts []string
	for _, k := range sortedKeys(v.expect[host]) {
		for _, val := range v.expect[host][k] {
			opts = append(opts, k+"="+val)
		}
	}
	return opts
}

// predictExpect asks ssh, BEFORE anything is written, how it prints the
// expected values of the plan: for every host with expectations,
// `ssh -F <main> -G -o key=value ... -- host` with ALL its expected values
// (the mechanism of predictDerived; pred is its result and is reused when the
// arguments are the same). ssh prints many values in its own form
// ("StrictHostKeyChecking yes" as "true", "ControlPersist 10m" as "600",
// "LogLevel debug" as "DEBUG", "LocalForward 8080 localhost:80" as
// "8080 [localhost]:80", "HostName Foo" as "foo", "~" and tokens expanded),
// so the text of a value says little; ssh's own rendering is exact.
//
// The result maps host -> expected option -> the values ssh prints for it
// with the overrides in place. Two refusals, both before any write:
//   - ssh rejects one of the values (an error from ssh);
//   - ssh prints no line for the option, neither now nor with the new value
//     (an option it ignores or never prints): nothing could show that the
//     edit took effect.
func (a *App) predictExpect(before map[string]string, pred map[string]map[string][]string, v verifyPlan) (map[string]map[string][]string, error) {
	rendered := map[string]map[string][]string{}
	for _, h := range sortedKeys(v.expect) {
		opts := expectOverrides(v, h)
		if len(opts) == 0 {
			continue
		}
		vals := pred[h]
		if vals == nil || !slices.Equal(opts, sourceOverrides(v, h)) {
			out, err := a.sshG(h, opts...)
			if err != nil {
				return nil, fmt.Errorf("ssh does not accept the new values (%s): %w", strings.Join(opts, ", "), err)
			}
			vals = optionValues(out)
		}
		b := optionValues(before[h])
		rendered[h] = map[string][]string{}
		for k := range v.expect[h] {
			if len(vals[k]) == 0 && len(b[k]) == 0 {
				return nil, fmt.Errorf("cannot verify the change: ssh -G %s shows no %s line, not even with the new value %s (ssh ignores the option or never prints it)",
					h, k, quoteAll(v.expect[h][k]))
			}
			rendered[h][k] = vals[k]
		}
	}
	return rendered, nil
}

// checkExpect verifies that every expected value of v.expect is in effect,
// exactly as ssh renders it. rendered is the result of predictExpect.
//
// For each host and expected option, with B the option's values before the
// save, P the values ssh predicted for the expected values and A the values
// after the save (all as `ssh -G` prints them):
//   - what the expected values ADD to the output (P minus B, as multisets)
//     must be in A. For an ordinary option that is the one new value, and A
//     is then exactly it; for a list option (IdentityFile, LocalForward) it
//     is the added value, which A only has to contain;
//   - when they add nothing, the value is one that is already in effect (or
//     that ssh folds into an existing one): A must still contain P;
//   - when they only take lines away ("ProxyCommand none"), A must be P.
//
// There is no "the option changed, so it is fine" shortcut: a save that
// writes "User dave" where the plan expects carol is refused, whatever else
// the configuration holds. An option that did not move at all is reported as
// an edit without effect (ssh's first value wins: an earlier block or file
// sets it), any other mismatch names the expected and the actual value.
func checkExpect(before, after map[string]string, rendered map[string]map[string][]string, v verifyPlan) error {
	for _, h := range sortedKeys(v.expect) {
		b, a := optionValues(before[h]), optionValues(after[h])
		for _, k := range sortedKeys(v.expect[h]) {
			p, ok := rendered[h][k]
			if !ok {
				return fmt.Errorf("verification failed: no prediction for %s of %s (internal error)", k, h)
			}
			added := multisetMinus(p, b[k])
			good := false
			switch {
			case len(added) > 0:
				good = len(multisetMinus(added, a[k])) == 0
			case len(p) < len(b[k]):
				good = len(multisetMinus(a[k], p)) == 0 && len(multisetMinus(p, a[k])) == 0
			default:
				good = len(multisetMinus(p, a[k])) == 0
			}
			if good {
				continue
			}
			now := "unset"
			if len(a[k]) > 0 {
				now = strings.Join(a[k], ", ")
			}
			want := quoteAll(v.expect[h][k])
			if slices.Equal(b[k], a[k]) {
				return fmt.Errorf("verification failed: the change had no effect: ssh -G %s still resolves %s as %s, not %s (an earlier Host/Match block or an earlier file sets it first, or ssh ignores the option)",
					h, k, now, want)
			}
			shown := added
			if len(shown) == 0 {
				shown = p
			}
			as := "unset"
			if len(shown) > 0 {
				as = strings.Join(shown, ", ")
			}
			return fmt.Errorf("verification failed: ssh -G %s resolves %s as %s, but the expected value %s must give %s",
				h, k, now, want, as)
		}
	}
	return nil
}

// multisetMinus returns the elements of a that b does not account for, in
// a's order: each element of b cancels one equal element of a.
func multisetMinus(a, b []string) []string {
	count := map[string]int{}
	for _, x := range b {
		count[x]++
	}
	var out []string
	for _, x := range a {
		if count[x] > 0 {
			count[x]--
			continue
		}
		out = append(out, x)
	}
	return out
}

// quoteAll renders values as a comma-separated list of quoted strings.
func quoteAll(values []string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, ", ")
}

// sortedKeys returns the keys of m in sorted order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// valueDiff describes how the values of option key differ: "- key value"
// (only before) and "+ key value" (only after) as multisets, or one "~" line
// when only the order changed.
func valueDiff(key string, before, after []string) []string {
	count := map[string]int{}
	for _, v := range before {
		count[v]++
	}
	for _, v := range after {
		count[v]--
	}
	var out []string
	for v, c := range count {
		for ; c > 0; c-- {
			out = append(out, "- "+key+" "+v)
		}
		for ; c < 0; c++ {
			out = append(out, "+ "+key+" "+v)
		}
	}
	if len(out) == 0 {
		return []string{fmt.Sprintf("~ %s order changed: [%s] -> [%s]", key, strings.Join(before, ", "), strings.Join(after, ", "))}
	}
	sort.Strings(out)
	return out
}
