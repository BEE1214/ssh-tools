package domain

import (
	"fmt"
	"strings"
)

// Severity classifies a validation issue.
type Severity int

const (
	SeverityError   Severity = iota // blocks save
	SeverityWarning                 // shows but doesn't block
	SeverityInfo                    // cosmetic / informational
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
	HostName string // empty for file-level issues
	Severity Severity
	Rule     string // machine-readable rule name
	Message  string // human-readable description
	Line     int    // 1-indexed line number, 0 if unknown
	File     string // config file the issue is in; empty if unknown or the main file
}

// Validate checks a list of hosts and returns all issues found.
// Issues are ordered by line number.
func Validate(hosts []Host) []Issue {
	var issues []Issue

	// seenNames is keyed by (file, name): a duplicate is an error only within
	// one file. The same name in two files is the weaker dup-host-cross-file
	// warning (ssh merges both and the first value wins).
	seenNames := make(map[string]int)    // file\x00name -> first line
	firstFile := make(map[string]string) // name -> file of its first definition

	type portOccurrence struct {
		host string
		line int
		file string
	}
	listenPorts := make(map[string][]portOccurrence)

	for _, h := range hosts {
		// Duplicate host name
		nameKey := h.SourceFile + "\x00" + h.Name
		if prevLine, ok := seenNames[nameKey]; ok {
			issues = append(issues, Issue{
				HostName: h.Name,
				Severity: SeverityError,
				Rule:     "duplicate-host",
				Message:  fmt.Sprintf("host %q already defined on line %d", h.Name, prevLine),
				Line:     h.LineStart,
				File:     h.SourceFile,
			})
		} else {
			seenNames[nameKey] = h.LineStart
		}
		if first, ok := firstFile[h.Name]; !ok {
			firstFile[h.Name] = h.SourceFile
		} else if first != h.SourceFile && isConcreteName(h.Name) {
			issues = append(issues, Issue{
				HostName: h.Name,
				Severity: SeverityWarning,
				Rule:     "dup-host-cross-file",
				Message:  fmt.Sprintf("host %q is also defined in %s (ssh merges both, first value wins)", h.Name, first),
				Line:     h.LineStart,
				File:     h.SourceFile,
			})
		}

		// Missing IdentityFile (not applicable to wildcard)
		if !h.IsWildcard() && !h.HasIdentityFile() {
			issues = append(issues, Issue{
				HostName: h.Name,
				Severity: SeverityWarning,
				Rule:     "missing-identity",
				Message:  "no IdentityFile set (will use ssh-agent or default key)",
				Line:     h.LineStart,
				File:     h.SourceFile,
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
				File:     h.SourceFile,
			})
		}

		// DevPod hosts are managed externally — skip structural checks
		if h.Source == SourceDevPod {
			continue
		}

		// Forward entries — skipped for wildcard (a Host * block's forwards
		// are inherited defaults, not a directly connectable target).
		if !h.IsWildcard() {
			checkForwards := func(kind ForwardKind, entries []string) {
				for _, entry := range entries {
					if err := ValidateForwardEntry(kind, entry); err != nil {
						issues = append(issues, Issue{
							HostName: h.Name,
							Severity: SeverityError,
							Rule:     "invalid-forward",
							Message:  err.Error(),
							Line:     h.LineStart,
							File:     h.SourceFile,
						})
						continue
					}
					port := ListenPort(kind, entry)
					listenPorts[port] = append(listenPorts[port], portOccurrence{host: h.Name, line: h.LineStart, file: h.SourceFile})
				}
			}
			checkForwards(ForwardLocal, h.LocalForwards)
			checkForwards(ForwardRemote, h.RemoteForwards)
			checkForwards(ForwardDynamic, h.DynamicForwards)
		}

		// Duplicate keys within a block (check Extra + known fields)
		// This is detected at parse time; here we just check for common patterns.
	}

	// Duplicate listen ports across the whole config (collected above,
	// after the per-host loop so every host's entries are known).
	ports := make([]string, 0, len(listenPorts))
	for port := range listenPorts {
		ports = append(ports, port)
	}
	for i := 1; i < len(ports); i++ {
		for j := i; j > 0 && ports[j-1] > ports[j]; j-- {
			ports[j-1], ports[j] = ports[j], ports[j-1]
		}
	}
	for _, port := range ports {
		occurrences := listenPorts[port]
		if len(occurrences) < 2 {
			continue
		}
		for _, occ := range occurrences {
			issues = append(issues, Issue{
				HostName: occ.host,
				Severity: SeverityWarning,
				Rule:     "duplicate-listen-port",
				Message:  fmt.Sprintf("listen port %s is configured in more than one place", port),
				Line:     occ.line,
				File:     occ.file,
			})
		}
	}

	// Sort by line number
	for i := 1; i < len(issues); i++ {
		for j := i; j > 0 && issues[j-1].Line > issues[j].Line; j-- {
			issues[j-1], issues[j] = issues[j], issues[j-1]
		}
	}

	return issues
}

// isConcreteName reports whether a Host pattern names exactly one host (no
// wildcards, negation or multiple patterns). Pattern blocks such as "Host *"
// legitimately appear in several files.
func isConcreteName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "*?! \t")
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
