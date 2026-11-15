package app

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// groupState is the enable/disable state for one group.
type groupState struct {
	Group string
	// Total is the number of hosts in the group (enabled + disabled).
	Total int
	// Disabled lists the hosts currently commented out of the config under
	// this group's markers. Empty for enabled groups.
	Disabled []string
}

// groupStatePath returns the sidecar state file path (respects the same
// $SSH_AUTH_CONFIG override as the config file).
//
// In managed mode the sidecar belongs to the managed file
// (<managed path>.sshm-groups, R10); in legacy mode to the main file.
func (a *App) groupStatePath() string {
	if v, err := a.activeView(); err == nil && v != nil {
		return a.managedGroupStatePath()
	}
	return a.mainGroupStatePath()
}

func (a *App) mainGroupStatePath() string    { return a.configPath + ".sshm-groups" }
func (a *App) managedGroupStatePath() string { return a.ManagedPath() + ".sshm-groups" }

// readGroupState loads the group state file. A missing file is an empty
// state, not an error. Unknown group names (no matching hosts in config)
// are kept — they may refer to hosts whose blocks were removed by hand.
func (a *App) readGroupState() (map[string]bool, error) {
	return readGroupStateFile(a.groupStatePath())
}

// readGroupStateFile is readGroupState for an explicit sidecar path.
func readGroupStateFile(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("read group state: %w", err)
	}
	state := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		state[line] = true
	}
	return state, nil
}

// writeGroupState atomically persists the group state file.
func writeGroupState(path string, state map[string]bool) error {
	names := make([]string, 0, len(state))
	for name := range state {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf strings.Builder
	buf.WriteString("# sshm group state — groups whose host blocks are disabled\n")
	buf.WriteString("# (commented out of the ssh config by 'sshm groups disable')\n")
	for _, name := range names {
		buf.WriteString(name)
		buf.WriteString("\n")
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp.sshm-groups-*")
	if err != nil {
		return fmt.Errorf("write group state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(buf.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("write group state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write group state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write group state: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("write group state: %w", err)
	}
	return os.Rename(tmp.Name(), path)
}

// ListGroupsState returns group states sorted by name: every group that has
// hosts, plus disabled groups (whose only visible hosts are disabled ones).
func (a *App) ListGroupsState() ([]groupState, error) {
	l, err := a.loadAll()
	if err != nil {
		return nil, err
	}
	disabledSet, err := a.readGroupState()
	if err != nil {
		return nil, err
	}

	byGroup := domain.GroupHosts(l.Hosts)
	names := domain.GroupNames(byGroup)

	result := make([]groupState, 0, len(names)+len(disabledSet))
	for _, name := range names {
		gs := groupState{Group: name, Total: len(byGroup[name])}
		for _, h := range byGroup[name] {
			if h.Disabled {
				gs.Disabled = append(gs.Disabled, h.Name)
			}
		}
		result = append(result, gs)
	}

	// State-file groups with no visible hosts at all (fully disabled).
	extra := make([]string, 0)
	for name := range disabledSet {
		if !slices.Contains(names, name) {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		result = append(result, groupState{Group: name, Total: 0, Disabled: nil})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Group < result[j].Group })
	return result, nil
}

// disabledNames returns the sorted host names of disabled hosts in a slice.
func disabledNames(hosts []domain.Host) []string {
	var names []string
	for _, h := range hosts {
		if h.Disabled {
			names = append(names, h.Name)
		}
	}
	return names
}

// ensureGroupInMain is the group form of the transitional write guard: group
// disable/enable rewrites the main file, so it refuses when any member of the
// group is defined in an included file (a group split across files would end
// up half disabled). action is "disable" or "enable", used in the message.
func (a *App) ensureGroupInMain(action, group string) error {
	l, err := a.loadAll()
	if err != nil {
		return err
	}
	var parts []string
	for _, h := range l.Hosts {
		if h.Group != group || h.IsWildcard() || h.SourceFile == l.MainPath() {
			continue
		}
		parts = append(parts, fmt.Sprintf("host %q is defined in %s (included)", h.Name, h.SourceFile))
	}
	if len(parts) > 0 {
		return fmt.Errorf("cannot %s group %q: %s, which sshm cannot edit yet", action, group, strings.Join(parts, ", "))
	}
	return nil
}

// DisableGroup disables a group: host blocks are commented out of the ssh
// config (under marker comments) and the group is recorded in the sidecar
// state file. After this, raw `ssh <host>` fails to resolve and sshm
// connect/copy refuse the group's hosts.
func (a *App) DisableGroup(group string) error {
	if err := domain.ValidateGroupName(group); err != nil {
		return err
	}
	if v, err := a.activeView(); err != nil {
		return err
	} else if v != nil {
		return a.disableGroupManaged(v, group)
	}
	if err := a.ensureGroupInMain("disable", group); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}

	// Collect the group's members from CURRENT host state. Enabled hosts get
	// Disabled=true (the writer then emits them verbatim between markers);
	// already-disabled hosts are left as-is.
	targets := 0
	changed := false
	for i := range cfg.Hosts {
		h := &cfg.Hosts[i]
		if h.Disabled || h.Group != group {
			continue
		}
		targets++
		// Hosts outside this config file's line tracking (shouldn't happen
		// for enabled hosts) are skipped defensively.
		if h.LineStart <= 0 {
			continue
		}
		h.Disabled = true
		start := h.LineStart
		if start < 1 {
			start = 1
		}
		end := h.LineEnd
		if end < start {
			end = len(cfg.RawTextLines())
		}
		h.RawBlock = strings.Join(cfg.RawTextLines()[start-1:end], "\n")
		changed = true
	}
	if targets == 0 {
		return fmt.Errorf("group %q has no enabled hosts", group)
	}
	if changed {
		if err := a.save(cfg); err != nil {
			return err
		}
	}

	// Record in the sidecar state file (idempotent).
	state, err := a.readGroupState()
	if err != nil {
		return err
	}
	state[group] = true
	return writeGroupState(a.groupStatePath(), state)
}

// EnableGroup re-enables a disabled group: the commented host blocks between
// the group's markers are restored verbatim and the group is removed from
// the sidecar state file.
func (a *App) EnableGroup(group string) error {
	if err := domain.ValidateGroupName(group); err != nil {
		return err
	}
	if v, err := a.activeView(); err != nil {
		return err
	} else if v != nil {
		return a.enableGroupManaged(v, group)
	}
	if err := a.ensureGroupInMain("enable", group); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}

	restored := 0
	for i := range cfg.Hosts {
		h := &cfg.Hosts[i]
		if h.Disabled && h.Group == group {
			h.Disabled = false
			restored++
		}
	}

	state, err := a.readGroupState()
	if err != nil {
		return err
	}
	wasTracked := state[group]
	delete(state, group)

	if restored == 0 && !wasTracked {
		return fmt.Errorf("group %q is not disabled", group)
	}
	if restored > 0 {
		if err := a.save(cfg); err != nil {
			return err
		}
	}
	return writeGroupState(a.groupStatePath(), state)
}

// IsGroupDisabled reports whether a group currently counts as disabled:
// listed in the sidecar state file, or has disabled hosts and no enabled
// hosts in the config.
func (a *App) IsGroupDisabled(group string) (bool, error) {
	l, err := a.loadAll()
	if err != nil {
		return false, err
	}
	state, err := a.readGroupState()
	if err != nil {
		return false, err
	}
	if state[group] {
		return true, nil
	}
	enabled, disabled := 0, 0
	for _, h := range l.Hosts {
		if h.Group != group || h.IsWildcard() {
			continue
		}
		if h.Disabled {
			disabled++
		} else {
			enabled++
		}
	}
	return disabled > 0 && enabled == 0, nil
}

// isHostDisabled reports whether a host is currently disabled (commented
// out of the config). Wildcard/defaults blocks are never disabled.
func isHostDisabled(h domain.Host) bool {
	return h.Disabled && !h.IsWildcard()
}

// isHostGated reports whether a host must be refused/hidden: it is commented
// out of the config, or its group is recorded as disabled in the sidecar
// state file (covers hosts added to a group after it was disabled).
// Wildcard/defaults blocks are never gated.
func isHostGated(h domain.Host, state map[string]bool) bool {
	return !h.IsWildcard() && (h.Disabled || state[h.Group])
}

// ensureNotDisabled returns an error if the named host's group is disabled
// (commented out of the config or recorded in the state file). nil is
// returned when the host is not in the config (ad-hoc targets are never
// gated). An unreadable state file is an error: the gate fails closed.
func (a *App) ensureNotDisabled(cfg *config.ConfigFile, name string) error {
	return a.ensureHostNotDisabled(cfg.Hosts, name)
}

// ensureHostNotDisabled is ensureNotDisabled over a host list, so read paths
// can gate against the merged (Include-following) view.
func (a *App) ensureHostNotDisabled(hosts []domain.Host, name string) error {
	idx := findHostIndex(hosts, name)
	if idx == -1 {
		return nil
	}
	state, err := a.readGroupState()
	if err != nil {
		return err
	}
	h := hosts[idx]
	if isHostGated(h, state) {
		return fmt.Errorf(
			"host %q is in disabled group %q — run 'sshm groups enable %s' to re-enable it",
			name, h.Group, h.Group)
	}
	return nil
}
