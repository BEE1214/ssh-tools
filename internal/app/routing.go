package app

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Write routing (PLAN-p3-p4.md section 4, PLAN-p7.md). The write methods of App
// (AddHost, EditHost, ...) never re-serialize the main file: they patch lines
// of the managed file through config.Doc and save it with saveManagedDoc. Each
// of them starts with gate, so a config that is not set up is refused first.

// managedView is the loaded configuration of an App that is set up.
type managedView struct {
	l    *config.Loaded
	file config.File // the managed file as loaded (Path is what hosts carry as SourceFile)
}

// activeView loads the configuration and returns the managed view, or nil when
// the config is not set up (see ManagedActive).
func (a *App) activeView() (*managedView, error) {
	l, err := a.loadAll()
	if err != nil {
		return nil, err
	}
	return a.viewOf(l), nil
}

// viewOf returns the managed view of an already loaded configuration, or nil
// when it is not set up. activeView and Snapshot decide it through this.
func (a *App) viewOf(l *config.Loaded) *managedView {
	f, ok := l.Lookup(a.ManagedPath())
	if !ok || f.Conditional {
		return nil
	}
	return &managedView{l: l, file: f}
}

// managedHost returns the block of the managed file that defines name.
func (v *managedView) managedHost(name string) (domain.Host, bool) {
	for _, h := range v.l.Hosts {
		if h.Name == name && singleName(h) && h.SourceFile == v.file.Path {
			return h, true
		}
	}
	return domain.Host{}, false
}

// singleName reports whether h's Host line has at most one pattern, so that
// its Name is the one name a user types for it (a line without any pattern
// counts: its Name is its argument text).
func singleName(h domain.Host) bool { return len(h.PatternList()) <= 1 }

// has reports whether any loaded file defines a host block named name.
func (v *managedView) has(name string) bool {
	for _, h := range v.l.Hosts {
		if h.Name == name {
			return true
		}
	}
	return false
}

// unmanaged returns the refusal of a write addressed by name that is not a
// plain edit of a managed-file block: *UnmanagedHostError when a single-pattern
// block of that name is defined outside the managed file (R4), else
// *MultiPatternError when name is one pattern of a multi-pattern Host line, or
// that line's whole text (M1). A single-pattern block of that name always wins
// over a multi-pattern line (M2). A name that is defined in the managed file or
// nowhere returns nil; callers report "not found" themselves.
func (v *managedView) unmanaged(name string) error {
	if _, ok := v.managedHost(name); ok {
		return nil
	}
	for _, h := range v.l.Hosts {
		if h.Name == name && singleName(h) {
			return &UnmanagedHostError{Host: name, File: h.SourceFile, CanImport: h.SourceFile == v.l.MainPath()}
		}
	}
	return multiPatternOf(v.l.Hosts, name)
}

// multiPatternOf returns the *MultiPatternError for the first multi-pattern
// Host line of hosts that name addresses (one of its patterns or its whole
// text), nil when there is none.
func multiPatternOf(hosts []domain.Host, name string) error {
	for _, h := range hosts {
		if singleName(h) {
			continue
		}
		if h.Name == name || slices.Contains(h.PatternList(), name) {
			return &MultiPatternError{Host: h.Name, File: h.SourceFile, Line: h.LineStart}
		}
	}
	return nil
}

// gate is the first step of every method that writes an ssh config (P7 G1-G4):
// it returns the managed view, or ErrNotSetUp when the main file has no
// unconditional Include of the managed file or does not exist. Any other error
// of reading the configuration is returned as it is. It writes nothing.
func (a *App) gate() (*managedView, error) {
	v, err := a.activeView()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ErrNotSetUp
	case err != nil:
		return nil, err
	case v == nil:
		return nil, ErrNotSetUp
	}
	return v, nil
}

// readManagedDoc reads the managed file as a Doc (a symlink is followed).
func (a *App) readManagedDoc() (*config.Doc, error) {
	raw, err := os.ReadFile(a.ManagedPath())
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", a.ManagedPath(), err)
	}
	return config.ParseDoc(raw), nil
}

// editManagedDoc reads the managed file, lets fn change its Doc, and saves it
// under the verify plan fn returns. Nothing is written when fn changed no byte.
func (a *App) editManagedDoc(fn func(d *config.Doc) (verifyPlan, error)) error {
	d, err := a.readManagedDoc()
	if err != nil {
		return err
	}
	plan, err := fn(d)
	if err != nil {
		return err
	}
	if bytes.Equal(d.Bytes(), d.Base()) {
		return nil
	}
	_, err = a.saveManagedDoc(a.ManagedPath(), d, plan)
	return err
}

// ---- add / edit / delete / duplicate ---------------------------------------

func (a *App) addHostManaged(v *managedView, h domain.Host) error {
	if v.has(h.Name) {
		return fmt.Errorf("host %q already exists", h.Name)
	}
	if h.Group == "" {
		h.Group = domain.GroupFor(h.Name)
	}
	h.Source = domain.SourceManual
	return a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		if err := d.AppendBlock(h); err != nil {
			return verifyPlan{}, fmt.Errorf("add host %q: %w", h.Name, err)
		}
		return anyChangePlan(h.Name), nil
	})
}

// sshKeyName is the lower-case option name `ssh -G` prints for an edit key.
func sshKeyName(key string) string {
	k := strings.ToLower(key)
	if k == "pubkeyacceptedkeytypes" {
		return "pubkeyacceptedalgorithms"
	}
	return k
}

// wholeListKeys are replaced as a whole by an edit (EditHost sets THE identity
// file of the block, see applyChange).
var wholeListKeys = map[string]bool{"identityfile": true, "certificatefile": true}

// editTarget returns the managed-file block an edit of name would change, or
// the refusal EditHost returns: unmanaged, not found, disabled, DevPod.
// CheckEdit uses it too, so a preview refuses exactly what the write refuses.
func (v *managedView) editTarget(name string) (domain.Host, error) {
	if err := v.unmanaged(name); err != nil {
		return domain.Host{}, err
	}
	h, ok := v.managedHost(name)
	if !ok {
		return domain.Host{}, fmt.Errorf("host %q not found", name)
	}
	if err := ensureEditable(h); err != nil {
		return domain.Host{}, err
	}
	if h.Source == domain.SourceDevPod {
		return domain.Host{}, fmt.Errorf("host %q is managed by DevPod — edit via DevPod instead", name)
	}
	return h, nil
}

func (a *App) editHostManaged(v *managedView, name string, changes map[string]string) error {
	if _, err := v.editTarget(name); err != nil {
		return err
	}

	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var unsetTokens []string
	err := a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		plan := editPlan(name)
		for _, key := range keys {
			value := changes[key]
			ssh := sshKeyName(key)
			plan.keys[name][ssh] = true
			if value == "" {
				if err := d.UnsetOption(name, key); err != nil {
					return verifyPlan{}, fmt.Errorf("edit %s: %w", name, err)
				}
				if tokenSources[ssh] {
					unsetTokens = append(unsetTokens, key)
				}
				continue
			}
			err := d.SetOption(name, key, value)
			if wholeListKeys[ssh] && errors.Is(err, config.ErrAmbiguousOption) {
				// Several lines of the list: the edit replaces all of them.
				if err = d.UnsetOption(name, key); err == nil {
					err = d.SetOption(name, key, value)
				}
			}
			if err != nil {
				return verifyPlan{}, fmt.Errorf("edit %s: %w", name, err)
			}
			if plan.expect == nil {
				plan.expect = map[string]map[string][]string{name: {}}
			}
			plan.expect[name][ssh] = append(plan.expect[name][ssh], value)
		}
		return plan, nil
	})
	return tokenHint(err, unsetTokens)
}

// tokenHint explains a rolled-back clearing of User/HostName/Port/ProxyJump/
// HostKeyAlias (R9): ssh derives other options from them through % tokens
// (ControlPath ... %C), so removing the line changes those too.
func tokenHint(err error, cleared []string) error {
	var ve *verifyError
	if err == nil || len(cleared) == 0 || !errors.As(err, &ve) {
		return err
	}
	for _, k := range ve.keys {
		if tokenDerived[k] {
			return fmt.Errorf("%w\nclearing %s changes options that ssh derives from it through tokens (such as %%C in ControlPath); the edit was rolled back: set a value instead or edit the file by hand",
				err, strings.Join(cleared, ", "))
		}
	}
	return err
}

func (a *App) deleteHostManaged(v *managedView, name string) error {
	if err := v.unmanaged(name); err != nil {
		return err
	}
	h, ok := v.managedHost(name)
	if !ok {
		return fmt.Errorf("host %q not found", name)
	}
	if h.Source == domain.SourceDevPod {
		return fmt.Errorf("host %q is managed by DevPod — remove via DevPod instead", name)
	}
	return a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		if err := d.DeleteBlock(name); err != nil {
			return verifyPlan{}, fmt.Errorf("delete %s: %w", name, err)
		}
		return anyChangePlan(name), nil
	})
}

func (a *App) duplicateHostManaged(v *managedView, src, dst string) error {
	if err := v.unmanaged(src); err != nil {
		return err
	}
	h, ok := v.managedHost(src)
	if !ok {
		return fmt.Errorf("source host %q not found", src)
	}
	if err := ensureEditable(h); err != nil {
		return err
	}
	if v.has(dst) {
		return fmt.Errorf("host %q already exists", dst)
	}
	return a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		if err := d.DuplicateBlock(src, dst); err != nil {
			return verifyPlan{}, fmt.Errorf("duplicate %s: %w", src, err)
		}
		return anyChangePlan(dst), nil
	})
}

// ---- forwards, certificates ------------------------------------------------

func (a *App) addForwardManaged(v *managedView, host string, kind domain.ForwardKind, specs []string) error {
	if err := v.unmanaged(host); err != nil {
		return err
	}
	if err := a.ensureHostNotDisabled(v.l.Hosts, host); err != nil {
		return err
	}
	if !v.has(host) {
		return fmt.Errorf("host %q not found", host)
	}
	canon := make([]string, 0, len(specs))
	for _, spec := range specs {
		entry, err := domain.ParseForwardSpec(kind, spec)
		if err != nil {
			return err
		}
		canon = append(canon, entry)
	}
	key := kind.ConfigKey()
	return a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		kv := make([]string, 0, 2*len(canon))
		for _, entry := range canon {
			if err := d.AddOptionValue(host, key, entry); err != nil {
				return verifyPlan{}, fmt.Errorf("add forward to %s: %w", host, err)
			}
			kv = append(kv, key, entry)
		}
		return setPlan(host, kv...), nil
	})
}

func (a *App) clearForwardsManaged(v *managedView, host string) error {
	if err := v.unmanaged(host); err != nil {
		return err
	}
	if err := a.ensureHostNotDisabled(v.l.Hosts, host); err != nil {
		return err
	}
	if !v.has(host) {
		return fmt.Errorf("host %q not found", host)
	}
	return a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		for _, kind := range []domain.ForwardKind{domain.ForwardLocal, domain.ForwardRemote, domain.ForwardDynamic} {
			if err := d.UnsetOption(host, kind.ConfigKey()); err != nil {
				return verifyPlan{}, fmt.Errorf("clear forwards of %s: %w", host, err)
			}
		}
		return editPlan(host, "localforward", "remoteforward", "dynamicforward"), nil
	})
}

func (a *App) clearCertificateFileManaged(v *managedView, name string) error {
	if err := v.unmanaged(name); err != nil {
		return err
	}
	h, ok := v.managedHost(name)
	if !ok {
		return nil // host not found, nothing to clear
	}
	if err := ensureEditable(h); err != nil {
		return err
	}
	return a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		if err := d.UnsetOption(name, "CertificateFile"); err != nil {
			return verifyPlan{}, fmt.Errorf("clear CertificateFile of %s: %w", name, err)
		}
		return editPlan(name, "certificatefile"), nil
	})
}

// ---- groups (option A, PLAN-include.md section 7) ---------------------------

// groupUnmanagedError lists the hosts that keep a group from being disabled or
// enabled in managed mode: up to three, then "and N more".
type groupUnmanagedError struct {
	head string
	errs []*UnmanagedHostError
}

func (e *groupUnmanagedError) Error() string {
	var b strings.Builder
	b.WriteString(e.head)
	for i, u := range e.errs {
		if i == 3 {
			fmt.Fprintf(&b, "\n  and %d more", len(e.errs)-3)
			break
		}
		b.WriteString("\n  " + u.Error())
	}
	return b.String()
}

func (e *groupUnmanagedError) Unwrap() error { return e.errs[0] }

// groupOutsideManaged lists the members of group (disabledOnly: only disabled
// blocks) that live outside the managed file, in file order.
func (v *managedView) groupOutsideManaged(group string, disabledOnly bool) []*UnmanagedHostError {
	var out []*UnmanagedHostError
	for _, h := range v.l.Hosts {
		if h.Group != group || h.IsWildcard() || h.SourceFile == v.file.Path || (disabledOnly && !h.Disabled) {
			continue
		}
		out = append(out, &UnmanagedHostError{Host: h.Name, File: h.SourceFile, CanImport: h.SourceFile == v.l.MainPath()})
	}
	return out
}

// hasDisabledMember reports whether group has a disabled block in the managed file.
func (v *managedView) hasDisabledMember(group string) bool {
	for _, h := range v.l.Hosts {
		if h.Group == group && h.Disabled && !h.IsWildcard() && h.SourceFile == v.file.Path {
			return true
		}
	}
	return false
}

func (a *App) disableGroupManaged(v *managedView, group string) error {
	if outside := v.groupOutsideManaged(group, false); len(outside) > 0 {
		return &groupUnmanagedError{
			head: fmt.Sprintf("cannot disable group %q: every member must be defined in the managed file", group),
			errs: outside,
		}
	}
	var targets []string
	for _, h := range v.l.Hosts {
		if h.Group == group && !h.Disabled && !h.IsWildcard() && h.SourceFile == v.file.Path {
			targets = append(targets, h.Name)
		}
	}
	statePath := a.groupStatePath()
	if len(targets) == 0 {
		// Retry safety: the blocks may be disabled already while the sidecar
		// write of that earlier run failed. Then only the sidecar is missing.
		if !v.hasDisabledMember(group) {
			return fmt.Errorf("group %q has no enabled hosts", group)
		}
		state, err := a.readGroupState()
		if err != nil {
			return err
		}
		if state[group] {
			return fmt.Errorf("group %q has no enabled hosts", group)
		}
		state[group] = true
		return writeGroupState(statePath, state)
	}
	err := a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
		if err := d.DisableBlocks(targets, group); err != nil {
			return verifyPlan{}, fmt.Errorf("disable group %q: %w", group, err)
		}
		return anyChangePlan(targets...), nil
	})
	if err != nil {
		return err
	}
	state, err := a.readGroupState()
	if err != nil {
		return err
	}
	state[group] = true
	return writeGroupState(statePath, state)
}

func (a *App) enableGroupManaged(v *managedView, group string) error {
	if outside := v.groupOutsideManaged(group, true); len(outside) > 0 {
		return &groupUnmanagedError{
			head: fmt.Sprintf("cannot enable group %q: all its disabled blocks must be in the managed file", group),
			errs: outside,
		}
	}
	var names []string
	for _, h := range v.l.Hosts {
		if h.Group == group && h.Disabled && !h.IsWildcard() && h.SourceFile == v.file.Path {
			names = append(names, h.Name)
		}
	}
	statePath := a.groupStatePath()
	state, err := a.readGroupState()
	if err != nil {
		return err
	}
	wasTracked := state[group]
	delete(state, group)
	if len(names) == 0 && !wasTracked {
		return fmt.Errorf("group %q is not disabled", group)
	}
	if len(names) > 0 {
		err := a.editManagedDoc(func(d *config.Doc) (verifyPlan, error) {
			if err := d.EnableGroup(group); err != nil {
				return verifyPlan{}, fmt.Errorf("enable group %q: %w", group, err)
			}
			return anyChangePlan(names...), nil
		})
		if err != nil {
			return err
		}
	}
	return writeGroupState(statePath, state)
}

// ---- init (R11) ---------------------------------------------------------------

// initManaged appends the Host * defaults block to the END of the main file
// when no Host * exists in any loaded file, and leaves an existing one alone.
func (a *App) initManaged(v *managedView) (written bool, note string, err error) {
	for _, h := range v.l.Hosts {
		if h.IsWildcard() && !h.Disabled {
			return false, fmt.Sprintf("Host * is already defined at %s:%d; sshm does not rewrite it (edit it by hand to change the defaults)",
				h.SourceFile, h.LineStart), nil
		}
	}
	lines, err := config.BlockLines(defaultHost())
	if err != nil {
		return false, "", err
	}
	d := config.ParseDoc(v.l.Files[0].Cfg.Raw)
	if err := d.AppendRaw(lines); err != nil {
		return false, "", err
	}
	// The new block gives every host values it did not have: any change of what
	// a name resolves to is allowed, ssh just has to parse the result.
	plan := verifyPlan{changed: map[string]bool{"*": true}}
	for _, h := range v.l.Hosts {
		if h.Disabled {
			continue
		}
		for _, n := range h.PatternList() {
			if probeable(n) {
				plan.probe = append(plan.probe, n)
			}
		}
	}
	note, err = a.saveMainDoc(d, plan) // a note says that the check was skipped
	if err != nil {
		return false, "", err
	}
	return true, note, nil
}
