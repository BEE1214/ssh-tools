package app

import (
	"fmt"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// HostEntry is a host plus the gate state a UI needs to decide what it may
// offer. Gated hosts (commented out of the config, or in a group recorded as
// disabled) must not be connected, edited or deleted.
type HostEntry struct {
	domain.Host
	Gated bool
	// Included is true when the host is defined only in files pulled in by
	// Include, not in the main config file. sshm cannot edit those yet.
	Included bool
	// ReadOnlyReason is "" when the location allows edit, duplicate and delete
	// (managed mode: the host is defined in the managed file; legacy mode: it
	// is defined in the main file). Otherwise it is the refusal message the
	// write would return (the *UnmanagedHostError text, or the legacy
	// "included" refusal text). Gated and DevPod hosts are NOT reflected here.
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
	for _, h := range l.Hosts {
		snap.Hosts = append(snap.Hosts, HostEntry{
			Host:           h,
			Gated:          isHostGated(h, state),
			Included:       ensureInMainLoaded(l, h.Name) != nil,
			ReadOnlyReason: readOnlyReason(l, v, h.Name),
		})
	}
	return snap, nil
}

// readOnlyReason is the refusal a write to name would return (guardWrite, on
// the configuration already loaded): "" when sshm may write the host's block.
func readOnlyReason(l *config.Loaded, v *managedView, name string) string {
	var err error
	if v != nil {
		err = v.unmanaged(name)
	} else {
		err = ensureInMainLoaded(l, name)
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
// same refusal errors as EditHost (not found, disabled, DevPod-managed).
func (a *App) CheckEdit(name string, changes map[string]string) ([]domain.Issue, error) {
	v, err := a.activeView()
	if err != nil {
		return nil, err
	}
	if v != nil {
		h, err := v.editTarget(name)
		if err != nil {
			return nil, err
		}
		for key, value := range changes {
			applyChange(&h, key, value)
		}
		return domain.Validate([]domain.Host{h}), nil
	}
	if err := a.ensureInMain(name); err != nil {
		return nil, err
	}
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}
	idx := findHostIndex(cfg.Hosts, name)
	if idx == -1 {
		return nil, fmt.Errorf("host %q not found", name)
	}
	h := cfg.Hosts[idx]
	if err := ensureEditable(h); err != nil {
		return nil, err
	}
	if h.Source == domain.SourceDevPod {
		return nil, fmt.Errorf("host %q is managed by DevPod — edit via DevPod instead", name)
	}
	for key, value := range changes {
		applyChange(&h, key, value)
	}
	return domain.Validate([]domain.Host{h}), nil
}
