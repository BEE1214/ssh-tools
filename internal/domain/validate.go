package domain

import (
	"fmt"
	"strings"
)

// Severity classifies a validation issue.
type Severity int

const (
	SeverityError   Severity = iota // blocks save
	SeverityWarning                  // shows but doesn't block
	SeverityInfo                     // cosmetic / informational
)

func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	}
	return "unknown"
}

// Issue is a single validation finding about a host or the config file.
type Issue struct {
	HostName string  // empty for file-level issues
	Severity Severity
	Rule     string  // machine-readable rule name
	Message  string  // human-readable description
	Line     int     // 1-indexed line number, 0 if unknown
}

// Validate checks a list of hosts and returns all issues found.
// Issues are ordered by line number.
func Validate(hosts []Host) []Issue {
	var issues []Issue

	seenNames := make(map[string]int) // name -> first line

	for _, h := range hosts {
		// Duplicate host name
		if prevLine, ok := seenNames[h.Name]; ok {
			issues = append(issues, Issue{
				HostName: h.Name,
				Severity: SeverityError,
				Rule:     "duplicate-host",
				Message:  fmt.Sprintf("host %q already defined on line %d", h.Name, prevLine),
				Line:     h.LineStart,
			})
		} else {
			seenNames[h.Name] = h.LineStart
		}

		// Missing IdentityFile (not applicable to wildcard)
		if !h.IsWildcard() && !h.HasIdentityFile() {
			issues = append(issues, Issue{
				HostName: h.Name,
				Severity: SeverityWarning,
				Rule:     "missing-identity",
				Message:  "no IdentityFile set (will use ssh-agent or default key)",
				Line:     h.LineStart,
			})
		}

		// StrictHostKeyChecking no
		if strings.EqualFold(h.StrictHostKeyChecking, "no") {
			issues = append(issues, Issue{
				HostName: h.Name,
				Severity: SeverityWarning,
				Rule:     "strict-no",
				Message:  "StrictHostKeyChecking no — consider accept-new",
				Line:     h.LineStart,
			})
		}

		// DevPod hosts are managed externally — skip structural checks
		if h.Source == SourceDevPod {
			continue
		}

		// Duplicate keys within a block (check Extra + known fields)
		// This is detected at parse time; here we just check for common patterns.
	}

	// Sort by line number
	for i := 1; i < len(issues); i++ {
		for j := i; j > 0 && issues[j-1].Line > issues[j].Line; j-- {
			issues[j-1], issues[j] = issues[j], issues[j-1]
		}
	}

	return issues
}

// HasErrors returns true if any issue has SeverityError.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == SeverityError {
			return true
		}
	}
	return false
}

// FilterByHost returns only issues for the given host name.
func FilterByHost(issues []Issue, name string) []Issue {
	var result []Issue
	for _, i := range issues {
		if i.HostName == name {
			result = append(result, i)
		}
	}
	return result
}