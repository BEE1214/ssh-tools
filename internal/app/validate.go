package app

import (
	"sort"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Validate checks the config file and every file it includes, and returns all
// issues found. Include problems (unreadable file, cycle, ...) are reported as
// warnings. Issues in included files carry Issue.File.
func (a *App) Validate() ([]domain.Issue, error) {
	l, err := a.loadAll()
	if err != nil {
		return nil, err
	}
	return validateLoaded(l), nil
}

// validateLoaded runs the host rules over the merged view, grouped by file in
// evaluation order, then appends the load warnings. Issue.File is cleared for
// the main file so presentation layers only mention files that are not it.
func validateLoaded(l *config.Loaded) []domain.Issue {
	issues := domain.Validate(l.Hosts)
	// Algorithm names need `ssh -Q`, which the pure domain package must not run.
	issues = append(issues, algorithmIssues(l.Hosts)...)

	order := make(map[string]int, len(l.Files))
	for i, f := range l.Files {
		order[f.Path] = i
	}
	sort.SliceStable(issues, func(i, j int) bool {
		if oi, oj := order[issues[i].File], order[issues[j].File]; oi != oj {
			return oi < oj
		}
		return issues[i].Line < issues[j].Line
	})
	for i := range issues {
		if issues[i].File == l.MainPath() {
			issues[i].File = ""
		}
	}

	for _, w := range l.Warnings {
		issues = append(issues, domain.Issue{
			Severity: domain.SeverityWarning,
			Rule:     "include",
			Message:  w,
		})
	}
	return issues
}

// Dump returns the effective config for a given host (what ssh -G shows),
// including blocks from included files.
func (a *App) Dump(name string) (domain.Host, error) {
	l, err := a.loadAll()
	if err != nil {
		return domain.Host{}, err
	}
	return domain.EffectiveConfig(l.Hosts, name)
}
