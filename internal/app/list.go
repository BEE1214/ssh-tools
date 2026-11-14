package app

import (
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// ListHosts returns all hosts, optionally filtered by group. Disabled hosts
// are excluded unless includeDisabled is set.
// If group is empty, all hosts are returned.
func (a *App) ListHosts(group string, includeDisabled bool) ([]domain.Host, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}

	var state map[string]bool
	if !includeDisabled {
		if state, err = a.readGroupState(); err != nil {
			return nil, err
		}
	}

	var filtered []domain.Host
	for _, h := range cfg.Hosts {
		if !includeDisabled && isHostGated(h, state) {
			continue
		}
		if group == "" || h.Group == group || (h.Group == "" && group == "ungrouped") {
			filtered = append(filtered, h)
		}
	}
	return filtered, nil
}

// ListGroups returns a map of group name to hosts in that group.
func (a *App) ListGroups() (map[string][]domain.Host, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}
	return domain.GroupHosts(cfg.Hosts), nil
}

// HostNamesForCompletion returns host names matching the query, for shell
// completion. Uses fuzzy matching when query is non-empty, alphabetical
// when empty. Excludes wildcard hosts.
func (a *App) HostNamesForCompletion(query string) ([]string, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}

	state, err := a.readGroupState()
	if err != nil {
		return nil, err
	}

	// Exclude wildcard hosts and hosts in disabled groups from completion.
	var hosts []domain.Host
	for _, h := range cfg.Hosts {
		if h.IsWildcard() || isHostGated(h, state) {
			continue
		}
		hosts = append(hosts, h)
	}

	return domain.FuzzyMatch(hosts, query), nil
}