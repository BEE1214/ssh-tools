package app

import (
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// ListHosts returns all hosts, optionally filtered by group.
// If group is empty, all hosts are returned.
func (a *App) ListHosts(group string) ([]domain.Host, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}

	if group == "" {
		return cfg.Hosts, nil
	}

	var filtered []domain.Host
	for _, h := range cfg.Hosts {
		if h.Group == group || (h.Group == "" && group == "ungrouped") {
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