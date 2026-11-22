package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// managedPathFor returns the managed file that belongs to the main ssh config
// main: <dir of main>/config.d/sshm.conf.
func managedPathFor(main string) string {
	return filepath.Join(filepath.Dir(main), "config.d", "sshm.conf")
}

var (
	// ErrImportConflict: a host name to move is already defined in the managed
	// file. Raised before any write; --force does not override it (I6).
	ErrImportConflict = errors.New("import conflict: host already exists in the managed file")

	// ErrNotEquivalent: `ssh -G` resolves some host differently after the move.
	// Both files were restored unless --force was given (I5).
	ErrNotEquivalent = errors.New("import would change what ssh resolves")

	// ErrCannotVerify: ssh is missing or a loaded file has a 'Match ... exec'
	// line, so equivalence cannot be checked; --apply refuses unless --force
	// (I7).
	ErrCannotVerify = errors.New("cannot verify that the import preserves ssh behavior")
)

// Reasons a host block stays in the main file (I3). The texts are fixed.
const (
	StayWildcard     = "wildcard or pattern"
	StayMultiPattern = "multiple patterns"
	StayDevPod       = "DevPod block"
	StayMatch        = "Match block"
	StayIncluded     = "defined in an included file"
)

// ImportOptions are the options of Import.
type ImportOptions struct {
	// Apply performs the move; without it Import only plans (I2).
	Apply bool
	// Force keeps the move although equivalence is violated or cannot be
	// verified (I5, I7). It never overrides ErrImportConflict (I6).
	Force bool
}

// ImportBlock is one block to move from the main file to the managed file.
type ImportBlock struct {
	Name     string
	Group    string // set for every grouped block (explicit group comment or name-prefix heuristic), else ""
	Disabled bool   // the block is marker-disabled and moves with its markers (I3, I9)
	FromLine int    // 1-based, inclusive, in the main file: first attached comment line
	ToLine   int    // last line of the block
}

// ImportStay is a host that stays where it is (I3).
type ImportStay struct {
	Name string
	// File is the file that contains the Host/Match line: the main file, or the
	// included file for StayIncluded.
	File   string
	Line   int    // 1-based line of the Host/Match line in File
	Reason string // one of the Stay* constants
}

// ImportResult is the plan and, with Apply, the outcome of Import.
type ImportResult struct {
	// Move lists the blocks to move, in original order (I4).
	Move []ImportBlock
	// Stay lists what stays in the main file or in included files (I3).
	Stay []ImportStay
	// Applied: the files were written (I4).
	Applied bool
	// Checked is true only when the `ssh -G` comparison ran; a dry run never
	// runs it.
	Checked bool
	// Equivalent: `ssh -G` of every concrete host is identical before and
	// after (I5). Meaningful only when Checked.
	Equivalent bool
	// Diff has two entries per differing `ssh -G` line (I5):
	// "<host>: -<key> <old>" then "<host>: +<key> <new>".
	Diff []string
	// Notes carries non-fatal remarks, e.g. skipped verification (I7).
	Notes []string
}

// afterImportPlan runs between planning and the first write of an applied
// import. A variable so tests can change the files at exactly that point
// (I12).
var afterImportPlan = func() {}

// importPlan is everything Import decided from the files as they were read.
type importPlan struct {
	l             *config.Loaded
	mainRaw       []byte
	mainTarget    string
	managedRaw    []byte
	managedTarget string
	managedDoc    *config.Doc
	mainDoc       *config.Doc
	spans         []config.Span // line ranges of the moved blocks in the main file
	moveNames     [][]string    // every host name inside each moved block
	conflicts     []string      // moved names the managed file defines with different content
	resumed       []bool        // per span: the managed file already has exactly these lines (I11b)
	res           ImportResult
}

// argText is the raw argument text after the keyword of a Host/Match line.
func argText(line string) string {
	s := strings.TrimSpace(line)
	i := strings.IndexAny(s, " \t=")
	if i < 0 {
		return ""
	}
	return strings.TrimLeft(s[i:], " \t=")
}

// planImport reads the files and classifies the blocks of the main file (I3).
// ErrNotSetUp when the config is not set up; refuses a configuration with an
// Include sshm cannot follow (I1).
func (a *App) planImport() (*importPlan, error) {
	v, err := a.activeView()
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, ErrNotSetUp
	}
	if err := trustLoaded(v.l); err != nil {
		return nil, fmt.Errorf("not importing: %w", err)
	}
	p := &importPlan{l: v.l, mainRaw: v.l.Files[0].Cfg.Raw}
	main := v.l.MainPath()
	if p.mainTarget, err = config.WriteTarget(a.configPath); err != nil {
		return nil, err
	}
	if p.managedTarget, err = config.WriteTarget(a.ManagedPath()); err != nil {
		return nil, err
	}
	if p.managedRaw, _, err = readState(p.managedTarget); err != nil {
		return nil, fmt.Errorf("read %s: %w", a.ManagedPath(), err)
	}
	p.managedDoc = config.ParseDoc(p.managedRaw)
	p.mainDoc = config.ParseDoc(p.mainRaw)

	// The parser knows what the Doc does not: DevPod blocks and the group of a
	// host (an explicit "# group:" comment beats the name-prefix heuristic).
	hostAt := map[int]domain.Host{}
	for _, h := range v.l.Files[0].Cfg.Hosts {
		if !h.Disabled && h.LineStart > 0 {
			hostAt[h.LineStart] = h
		}
	}

	res := &p.res
	for _, b := range p.mainDoc.Blocks() {
		line := p.mainDoc.Lines[b.HostLine]
		switch {
		case b.Disabled:
			hosts := p.mainDoc.RegionHosts(b)
			if len(hosts) == 0 {
				continue // a region with no host in it is just commented-out text: it stays
			}
			// One entry per host. The region moves as a whole (markers
			// included), so the entries split its lines into consecutive
			// ranges: the first starts at the start marker, the last ends at
			// the end marker.
			for i, h := range hosts {
				from, to := h.Line, b.End
				if i == 0 {
					from = b.Start
				}
				if i+1 < len(hosts) {
					to = hosts[i+1].Line
				}
				res.Move = append(res.Move, ImportBlock{
					Name: strings.Join(h.Names, " "), Group: b.Group, Disabled: true, FromLine: from + 1, ToLine: to,
				})
			}
			p.spans = append(p.spans, config.Span{From: b.Start, To: b.End})
			p.moveNames = append(p.moveNames, b.Names)
		case b.Match:
			res.Stay = append(res.Stay, ImportStay{Name: argText(line), File: main, Line: b.HostLine + 1, Reason: StayMatch})
		case len(b.Names) > 1:
			res.Stay = append(res.Stay, ImportStay{Name: argText(line), File: main, Line: b.HostLine + 1, Reason: StayMultiPattern})
		case len(b.Names) == 0 || strings.ContainsAny(b.Names[0], "*?!"):
			res.Stay = append(res.Stay, ImportStay{Name: argText(line), File: main, Line: b.HostLine + 1, Reason: StayWildcard})
		default:
			h := hostAt[b.HostLine+1]
			if h.Source == domain.SourceDevPod {
				res.Stay = append(res.Stay, ImportStay{Name: argText(line), File: main, Line: b.HostLine + 1, Reason: StayDevPod})
				continue
			}
			group := h.Group
			if _, parsed := hostAt[b.HostLine+1]; !parsed {
				group = domain.GroupFor(b.Names[0])
			}
			// A "# DevPod End" line directly above the Host line closes the
			// block above; it is not this block's comment.
			start := b.Start
			for start < b.HostLine && strings.HasPrefix(strings.TrimSpace(p.mainDoc.Lines[start]), "# DevPod End ") {
				start++
			}
			res.Move = append(res.Move, ImportBlock{Name: b.Names[0], Group: group, FromLine: start + 1, ToLine: b.End})
			p.spans = append(p.spans, config.Span{From: start, To: b.End})
			p.moveNames = append(p.moveNames, b.Names)
		}
	}
	for _, h := range v.l.Hosts {
		if h.SourceFile == main || h.SourceFile == v.file.Path || h.Disabled || h.LineStart <= 0 {
			continue
		}
		res.Stay = append(res.Stay, ImportStay{Name: h.Name, File: h.SourceFile, Line: h.LineStart, Reason: StayIncluded})
	}

	// I6: names the managed file already defines. I11b: a block whose raw lines
	// are byte-identical to one in the managed file is the leftover of an
	// interrupted import, not a conflict; only its removal from the main file is
	// still due.
	have := map[string]bool{}
	haveRaw := map[string]bool{}
	for _, b := range p.managedDoc.Blocks() {
		if !b.Match {
			haveRaw[strings.Join(p.managedDoc.Raw(b), "\n")] = true
			for _, n := range b.Names {
				have[n] = true
			}
		}
	}
	seen := map[string]bool{}
	p.resumed = make([]bool, len(p.spans))
	anyResumed := false
	for i, names := range p.moveNames {
		s := p.spans[i]
		if haveRaw[strings.Join(p.mainDoc.Lines[s.From:s.To], "\n")] {
			p.resumed[i] = true
			anyResumed = true
			continue
		}
		for _, n := range names {
			if have[n] && !seen[n] {
				seen[n] = true
				p.conflicts = append(p.conflicts, n)
			}
		}
	}
	if anyResumed {
		res.Notes = append(res.Notes, "resuming an interrupted import")
	}
	return p, nil
}

// Import moves the plain single-name Host blocks (and marker-disabled blocks)
// of the main file into the managed file (I1-I12). It plans only unless
// opts.Apply is set. Returns ErrNotSetUp when the config is not set up,
// ErrConflict (I12) when a file changed between planning and the write.
func (a *App) Import(opts ImportOptions) (ImportResult, error) {
	p, err := a.planImport()
	if err != nil {
		return ImportResult{}, err
	}
	res := p.res
	if len(res.Move) == 0 {
		return res, nil
	}
	if !opts.Apply {
		res.Notes = append(res.Notes, "equivalence is checked when --apply runs")
		if len(p.conflicts) > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("--apply would stop: already defined in the managed file: %s", strings.Join(p.conflicts, ", ")))
		}
		return res, nil
	}
	if len(p.conflicts) > 0 {
		return res, fmt.Errorf("%w: %s", ErrImportConflict, strings.Join(p.conflicts, ", "))
	}
	skip := verifySkipReason(p.l, p.managedDoc, a.ManagedPath())
	if skip != "" {
		if !opts.Force {
			return res, fmt.Errorf("%w: %s; use --force to move without the check", ErrCannotVerify, skip)
		}
		res.Notes = append(res.Notes, "verification skipped: "+skip)
	}
	afterImportPlan()
	err = a.applyImport(p, opts, skip == "", &res)
	return res, err
}

// applyImport writes the plan (I4, I10-I12) and verifies it (I5).
func (a *App) applyImport(p *importPlan, opts ImportOptions, verify bool, res *ImportResult) (err error) {
	main, managed := a.configPath, a.ManagedPath()

	// Lock both files, always in the same order. Two paths in one directory
	// (a symlinked config.d) share one lock file, which must be taken once.
	var locks []string
	for _, f := range []string{main, managed} {
		lp, err := managedLockPath(f)
		if err != nil {
			return fmt.Errorf("not writing %s: %w", f, err)
		}
		if !slices.Contains(locks, lp) {
			locks = append(locks, lp)
		}
	}
	sort.Strings(locks)
	for _, lp := range locks {
		unlock, err := config.LockFile(lp, managedLockTimeout)
		if err != nil {
			return fmt.Errorf("not writing %s and %s: %w", main, managed, err)
		}
		defer unlock()
	}

	// I12: both files are still what the plan was made from. Checked again
	// after the ssh probes and before the backups and the writes.
	unchanged := func() error {
		for _, f := range []struct {
			path, target string
			want         []byte
		}{{main, p.mainTarget, p.mainRaw}, {managed, p.managedTarget, p.managedRaw}} {
			cur, _, err := readState(f.target)
			if err != nil {
				return fmt.Errorf("read %s: %w", f.path, err)
			}
			if !bytes.Equal(cur, f.want) {
				return fmt.Errorf("not writing %s: %w", f.path, ErrConflict)
			}
		}
		return nil
	}
	if err := unchanged(); err != nil {
		return err
	}

	var names []string
	var before map[string]string
	if verify {
		var err error
		if names, err = probeNames(p.l, p.managedDoc, verifyPlan{}); err != nil {
			return fmt.Errorf("not importing: %w", err)
		}
		if before, err = a.resolveAll(names); err != nil {
			hint := a.backupHint(main)
			if hint == "" {
				hint = a.backupHint(managed)
			}
			return fmt.Errorf("not importing: the current ssh configuration is already broken: %w%s", err, hint)
		}
		if err := unchanged(); err != nil {
			return err
		}
	}

	// The new contents.
	// Blocks the managed file already has (I11b) are only removed from main.
	var moved []string
	for i, s := range p.spans {
		if p.resumed[i] {
			continue
		}
		if len(moved) > 0 {
			moved = append(moved, "")
		}
		moved = append(moved, p.mainDoc.Lines[s.From:s.To]...)
	}
	newManaged := config.ParseDoc(p.managedRaw)
	if err := newManaged.AppendRaw(moved); err != nil {
		return fmt.Errorf("not importing: %w", err)
	}
	newMain := config.ParseDoc(p.mainRaw)
	if err := newMain.RemoveSpans(p.spans); err != nil {
		return fmt.Errorf("not importing: %w", err)
	}
	managedData, mainData := newManaged.Bytes(), newMain.RawBytes()
	if len(moved) == 0 {
		managedData = p.managedRaw // everything is there already (I11b): keep its bytes as they are
	}
	managedMode := os.FileMode(0o600)
	if fi, err := os.Stat(p.managedTarget); err == nil {
		managedMode = fi.Mode().Perm()
	}

	// I10: back up both files first.
	if _, err := config.BackupTo(p.managedTarget, a.managedBackupDir()); err != nil {
		return fmt.Errorf("backup %s: %w", managed, err)
	}
	if _, err := config.BackupTo(p.mainTarget, a.managedBackupDir()); err != nil {
		return fmt.Errorf("backup %s: %w", main, err)
	}
	if err := unchanged(); err != nil {
		return err
	}

	// I11: managed first, then main; a failed main write puts the managed file back.
	restoreManaged := func() error {
		return restoreFile(kindManaged, managed, managedData, p.managedRaw, true, managedMode)
	}
	// From the first write to the end of the verification a signal restores
	// both files like a failed verification (interrupt.go).
	w := a.openInterruptWindow()
	defer func() { a.closeInterruptWindow(w, err) }()
	if err := config.AtomicWriteMode(managed, managedData, 0o600); err != nil {
		if rerr := restoreManaged(); rerr != nil {
			return fmt.Errorf("write %s: %w (AND restoring it failed: %v)", managed, err, rerr)
		}
		return fmt.Errorf("write %s: %w", managed, err)
	}
	if err := writeMainFile(main, mainData); err != nil {
		if rerr := restoreManaged(); rerr != nil {
			return fmt.Errorf("write %s: %w (AND restoring %s failed: %v)", main, err, managed, rerr)
		}
		return fmt.Errorf("write %s: %w (nothing was moved: %s was restored)", main, err, managed)
	}
	restoreBoth := func(cause error) error {
		merr := restoreFile(kindMain, main, mainData, p.mainRaw, true, 0)
		gerr := restoreManaged()
		if w.fired() {
			return a.interrupted(w, main, errors.Join(merr, gerr))
		}
		if merr != nil || gerr != nil {
			return fmt.Errorf("%w (AND the rollback failed: %v; backups are in %s)", cause, errors.Join(merr, gerr), a.managedBackupDir())
		}
		return cause
	}

	if w.fired() {
		return restoreBoth(ErrInterrupted)
	}

	// What ssh sees now.
	l2, err := a.loadAll()
	if err == nil {
		err = trustLoaded(l2)
	}
	if err == nil {
		err = managedIncluded(l2, managed)
	}
	if err != nil {
		return restoreBoth(fmt.Errorf("import undone, files restored: %w", err))
	}
	if verify {
		after, err := a.resolveAll(names)
		if err != nil {
			return restoreBoth(fmt.Errorf("import undone, files restored: %w", err))
		}
		res.Checked = true
		if diff := diffResolved(before, after); len(diff) > 0 {
			res.Diff = diff
			if !opts.Force {
				return restoreBoth(fmt.Errorf("%w; both files were restored", ErrNotEquivalent))
			}
		} else {
			res.Equivalent = true
		}
	}
	if w.fired() {
		res.Applied, res.Equivalent = false, false
		return restoreBoth(ErrInterrupted)
	}
	res.Applied = true
	return a.migrateGroupState(p, res)
}

// writeMainFile writes the main config atomically, keeping its mode and a
// symlink. A variable so tests can make the write fail.
var writeMainFile = func(path string, data []byte) error { return config.AtomicWrite(path, data) }

// migrateGroupState moves the sidecar entries of the groups whose disabled
// blocks were moved from <main>.sshm-groups to <managed>.sshm-groups (I9).
func (a *App) migrateGroupState(p *importPlan, res *ImportResult) error {
	groups := map[string]bool{}
	for _, b := range res.Move {
		if b.Disabled && b.Group != "" {
			groups[b.Group] = true
		}
	}
	if len(groups) == 0 {
		return nil
	}
	fail := func(err error) error {
		return fmt.Errorf("the blocks were moved, but the disabled-group state could not be migrated from %s to %s: %w",
			a.mainGroupStatePath(), a.managedGroupStatePath(), err)
	}
	mainState, err := readGroupStateFile(a.mainGroupStatePath())
	if err != nil {
		return fail(err)
	}
	var moving []string
	for g := range groups {
		if mainState[g] {
			moving = append(moving, g)
		}
	}
	if len(moving) == 0 {
		return nil
	}
	managedState, err := readGroupStateFile(a.managedGroupStatePath())
	if err != nil {
		return fail(err)
	}
	for _, g := range moving {
		managedState[g] = true
		delete(mainState, g)
	}
	if err := writeGroupState(a.managedGroupStatePath(), managedState); err != nil {
		return fail(err)
	}
	if err := writeGroupState(a.mainGroupStatePath(), mainState); err != nil {
		return fail(err)
	}
	return nil
}

// diffResolved lists, for every name whose `ssh -G` output differs between
// before and after, the differing option lines: "<name>: -<key> <old>" for a
// value that was there and is gone, "<name>: +<key> <new>" for a new one, the
// minus entries of a key first (I5, 5.1). Names are in sorted order.
func diffResolved(before, after map[string]string) []string {
	var out []string
	for _, n := range sortedKeys(before) {
		b, a := before[n], after[n]
		if b == a {
			continue
		}
		bk, bv := orderedOptions(b)
		ak, av := orderedOptions(a)
		keys := append([]string(nil), bk...)
		for _, k := range ak {
			if _, ok := bv[k]; !ok {
				keys = append(keys, k)
			}
		}
		start := len(out)
		for _, k := range keys {
			if slices.Equal(bv[k], av[k]) {
				continue
			}
			removed, added := multisetMinus(bv[k], av[k]), multisetMinus(av[k], bv[k])
			if len(removed) == 0 && len(added) == 0 { // same values, other order
				removed, added = bv[k], av[k]
			}
			for _, v := range removed {
				out = append(out, fmt.Sprintf("%s: -%s %s", n, k, v))
			}
			for _, v := range added {
				out = append(out, fmt.Sprintf("%s: +%s %s", n, k, v))
			}
		}
		if len(out) == start {
			out = append(out, n+": ~ the ssh -G output differs")
		}
	}
	return out
}

// orderedOptions is optionValues that also returns the keys in output order.
func orderedOptions(out string) (keys []string, vals map[string][]string) {
	vals = map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		if l == "" {
			continue
		}
		key, val, _ := strings.Cut(l, " ")
		if _, ok := vals[key]; !ok {
			keys = append(keys, key)
		}
		vals[key] = append(vals[key], val)
	}
	return keys, vals
}
