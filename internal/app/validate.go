package app

import (
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Validate checks the config file and returns all issues found:
// structural/semantic issues from the domain layer plus parse issues
// (dup-key, malformed-line) recorded while reading the file.
func (a *App) Validate() ([]domain.Issue, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}

	issues := domain.Validate(cfg.Hosts)

	// Prepend parse issues with correct relative ordering (they carry
	// their own line numbers; the sort below fixes ordering).
	for _, p := range cfg.Issues {
		issues = append(issues, domain.Issue{
			Severity: severityForParseRule(p.Rule),
			Rule:     p.Rule,
			Message:  p.Message,
			Line:     p.Line,
		})
	}

	sortByLine(issues)
	return issues, nil
}

// Lint runs the full check suite: config rules, parse issues, referenced
// file existence/permissions, and certificate expiry.
func (a *App) Lint() ([]domain.Issue, error) {
	issues, err := a.Validate()
	if err != nil {
		return nil, err
	}

	fileIssues, err := a.CheckFiles()
	if err != nil {
		return nil, err
	}
	issues = append(issues, fileIssues...)

	certIssues, err := a.CheckCertExpiry()
	if err != nil {
		return nil, err
	}
	issues = append(issues, certIssues...)

	sortByLine(issues)
	return issues, nil
}

// severityForParseRule maps a parse rule to an issue severity.
func severityForParseRule(rule string) domain.Severity {
	switch rule {
	case "dup-key":
		return domain.SeverityError
	default:
		return domain.SeverityWarning
	}
}

// sortByLine orders issues by line number (0/unknown last).
func sortByLine(issues []domain.Issue) {
	for i := 1; i < len(issues); i++ {
		for j := i; j > 0 && lineKey(issues[j-1]) > lineKey(issues[j]); j-- {
			issues[j-1], issues[j] = issues[j], issues[j-1]
		}
	}
}

func lineKey(i domain.Issue) int {
	if i.Line == 0 {
		return 1 << 30 // sort unknown lines last
	}
	return i.Line
}

// Dump returns the effective config for a given host (what ssh -G shows).
func (a *App) Dump(name string) (domain.Host, error) {
	cfg, err := a.load()
	if err != nil {
		return domain.Host{}, err
	}
	return domain.EffectiveConfig(cfg.Hosts, name)
}
