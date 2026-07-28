package app

import (
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Validate checks the config file and returns all issues found.
func (a *App) Validate() ([]domain.Issue, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}
	return domain.Validate(cfg.Hosts), nil
}

// Dump returns the effective config for a given host (what ssh -G shows).
func (a *App) Dump(name string) (domain.Host, error) {
	cfg, err := a.load()
	if err != nil {
		return domain.Host{}, err
	}
	return domain.EffectiveConfig(cfg.Hosts, name)
}