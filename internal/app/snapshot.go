package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// HostEntry is a host plus the gate state a UI needs to decide what it may
// offer. Gated hosts (commented out of the config, or in a group recorded as
// disabled) must not be connected, edited or deleted.
type HostEntry struct {
	// Host.Name is the name a user types, the one pattern of the Host line; a
	// trailing comment is not part of it (`Host web-9 # prod box` is web-9).
	// A line with several patterns has them joined by one space ("db-1 db-2"),
	// as there is no single name to type.
	domain.Host
	Gated bool
	// Included is true when the host is defined only in files pulled in by
	// Include, not in the main config file. sshm cannot edit those yet.
	Included bool
	// ReadOnlyReason is "" when the location allows edit, duplicate and delete
	// (set-up config: the host is defined in the managed file; config that is
	// not set up: it is defined in the main file). Otherwise it is the refusal
	// message the write would return: the *MultiPatternError text for a line
	// with several patterns, the *UnmanagedHostError text, or the "included"
	// refusal text of a config that is not set up. Gated and DevPod hosts are
	// NOT reflected here.
	ReadOnlyReason string
}

// Snapshot is a consistent, read-only view of the config for presentation
// layers: every host (including disabled ones) and the validation issues
// of the whole file. It is a point-in-time copy — mutations always re-read
// the file, so a stale Snapshot can never overwrite newer on-disk content.
type Snapshot struct {
	Hosts  []HostEntry
	Issues []domain.Issue
	// Managed is App.ManagedActive().
	Managed bool
	// ManagedPath is App.ManagedPath().
	ManagedPath string
	// ManagedProblem is non-empty exactly when a loaded file has an
	// UNCONDITIONAL Include that reaches ManagedPath, the managed file exists
	// and it could not be loaded (unreadable or unparsable). The text names the
	// managed path and the load warning. Managed is false then; a missing
	// managed file and a missing Include leave it empty.
	ManagedProblem string
}

// Snapshot reads the config once and returns all hosts with their gate state
// plus the file's validation issues.
func (a *App) Snapshot() (Snapshot, error) {
	l, err := a.loadAll()
	if err != nil {
		return Snapshot{}, err
	}
	state, err := a.readGroupState()
	if err != nil {
		return Snapshot{}, err
	}
	v := a.viewOf(l)
	snap := Snapshot{
		Hosts:       make([]HostEntry, 0, len(l.Hosts)),
		Issues:      validateLoaded(l),
		Managed:     v != nil,
		ManagedPath: a.ManagedPath(),
	}
	if v == nil {
		snap.ManagedProblem = managedLoadProblem(l, snap.ManagedPath)
	}
	for _, h := range l.Hosts {
		snap.Hosts = append(snap.Hosts, HostEntry{
			Host:           h,
			Gated:          isHostGated(h, state),
			Included:       ensureInMainLoaded(l, h.Name) != nil,
			ReadOnlyReason: readOnlyReason(l, v, h),
		})
	}
	return snap, nil
}

// managedLoadProblem explains why ssh reads the managed file while sshm could
// not load it: an unconditional Include reaches it (managedIncludeState), the
// file exists, and it is not among the loaded files, so Load recorded a
// warning for it (unreadable or unparsable). "" in every other case: a missing
// file (never created), no Include, or a conditional Include.
func managedLoadProblem(l *config.Loaded, managed string) string {
	if state, _ := managedIncludeState(l, managed); state != includeUnconditional {
		return ""
	}
	if _, err := os.Stat(managed); os.IsNotExist(err) {
		return ""
	}
	warning := ""
	for _, w := range l.Warnings {
		if strings.Contains(w, "include "+managed+":") {
			warning = w
			break
		}
	}
	if warning == "" {
		// Spelled differently (symlinks, ~): name the first blind spot instead.
		if len(l.Unfollowed) > 0 {
			warning = l.Unfollowed[0]
		} else {
			warning = "not loaded"
		}
	}
	return fmt.Sprintf("managed file cannot be loaded (%s): %s", shortLoadReason(warning, managed), managed)
}

// shortLoadReason strips the "<from>:<line>: cannot parse include <path>:"
// prefix(es) from a load warning so the reason does not repeat the (long)
// managed path. A reason that still contains the path is cut before it; when
// nothing useful remains the warning is returned as is.
func shortLoadReason(warning, managed string) string {
	reason := warning
	marker := "include " + managed + ":"
	for {
		i := strings.Index(reason, marker)
		if i < 0 {
			break
		}
		reason = strings.TrimSpace(reason[i+len(marker):])
	}
	if i := strings.Index(reason, managed); i >= 0 {
		reason = strings.TrimRight(strings.TrimSpace(reason[:i]), ": ")
	}
	// Keep the first sentence only (up to the first ": " outside quotes), so the
	// text stays short enough to wrap onto few lines beside the path.
	inQuote := false
	for i := 0; i+1 < len(reason); i++ {
		if reason[i] == '"' {
			inQuote = !inQuote
		} else if !inQuote && reason[i] == ':' && reason[i+1] == ' ' {
			reason = reason[:i]
			break
		}
	}
	if reason == "" {
		return warning
	}
	return reason
}

// readOnlyReason is the refusal a write to h would return, on the configuration
// already loaded: "" when sshm may write the host's block. A line with several
// patterns is read-only in both modes (M3); it is answered with its own
// location, whatever other blocks carry the same text.
func readOnlyReason(l *config.Loaded, v *managedView, h domain.Host) string {
	if !singleName(h) {
		return (&MultiPatternError{Host: h.Name, File: h.SourceFile, Line: h.LineStart}).Error()
	}
	var err error
	if v != nil {
		err = v.unmanaged(h.Name)
	} else {
		err = ensureInMainLoaded(l, h.Name)
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// CheckHostName reports why name cannot be used for a new host: it is
// empty, contains whitespace (which would define several host patterns), or
// already exists. It writes nothing.
func (a *App) CheckHostName(name string) error {
	if name == "" {
		return fmt.Errorf("host name must not be empty")
	}
	if strings.ContainsAny(name, " \t") {
		return fmt.Errorf("host name %q must not contain whitespace", name)
	}
	l, err := a.loadAll()
	if err != nil {
		return err
	}
	// Any loaded file counts. In managed mode "exists" is also what AddHost
	// decides (managedView.has matches the pattern, not the raw line text).
	if findHostIndex(l.Hosts, name) != -1 {
		return fmt.Errorf("host %q already exists", name)
	}
	if v := a.viewOf(l); v != nil && v.has(name) {
		return fmt.Errorf("host %q already exists", name)
	}
	return nil
}

// CheckNewHost previews the validation issues AddHost's input would produce:
// the name check plus the standard per-host rules. It writes nothing.
func (a *App) CheckNewHost(h domain.Host) ([]domain.Issue, error) {
	var issues []domain.Issue
	if err := a.CheckHostName(h.Name); err != nil {
		issues = append(issues, domain.Issue{
			HostName: h.Name,
			Severity: domain.SeverityError,
			Rule:     "host-name",
			Message:  err.Error(),
		})
	}
	return append(issues, domain.Validate([]domain.Host{h})...), nil
}

// CheckEdit previews the validation issues for host name after applying
// changes (same semantics as EditHost). It writes nothing. It returns the
// same refusal errors as EditHost (not set up, not found, disabled,
// DevPod-managed, not in the managed file, several patterns).
func (a *App) CheckEdit(name string, changes map[string]string) ([]domain.Issue, error) {
	v, err := a.gate()
	if err != nil {
		return nil, err
	}
	h, err := v.editTarget(name)
	if err != nil {
		return nil, err
	}
	for key, value := range changes {
		applyChange(&h, key, value)
	}
	return domain.Validate([]domain.Host{h}), nil
}
