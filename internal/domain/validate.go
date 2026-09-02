package domain

import (
	"fmt"
	"strconv"
	"strings"
	"time"
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
}

// Validate checks a list of hosts and returns all issues found.
// Issues are ordered by line number.
func Validate(hosts []Host) []Issue {
	var issues []Issue

	seenNames := make(map[string]int) // name -> first line
	wildcardSeen := false

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

		// Host * should be the first block — ssh config is first-match-wins,
		// so a Host * block after specific hosts never applies its defaults.
		if h.IsWildcard() {
			if wildcardSeen {
				issues = append(issues, Issue{
					HostName: h.Name,
					Severity: SeverityWarning,
					Rule:     "duplicate-wildcard",
					Message:  "more than one Host * block — only the first applies as defaults",
					Line:     h.LineStart,
				})
			}
			wildcardSeen = true
		}

		// Missing IdentityFile (not applicable to wildcard)
		if !h.IsWildcard() && !h.HasIdentityFile() && h.CertificateFile == "" {
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

		// Port validation
		if h.Port != "" {
			if msg := validatePort(h.Port); msg != "" {
				issues = append(issues, Issue{
					HostName: h.Name,
					Severity: SeverityError,
					Rule:     "invalid-port",
					Message:  msg,
					Line:     h.LineStart,
				})
			}
		}

		// Boolean option validation
		for field, value := range map[string]string{
			"ForwardAgent": h.ForwardAgent,
			"ForwardX11":   h.ForwardX11,
		} {
			if value == "" {
				continue
			}
			if !isValidBoolean(value) {
				issues = append(issues, Issue{
					HostName: h.Name,
					Severity: SeverityError,
					Rule:     "invalid-value",
					Message:  fmt.Sprintf("%s %q — expected yes/no", field, value),
					Line:     h.LineStart,
				})
			}
		}

		// StrictHostKeyChecking: yes/no/accept-new all valid.
		if h.StrictHostKeyChecking != "" {
			v := strings.ToLower(strings.TrimSpace(h.StrictHostKeyChecking))
			if v != "yes" && v != "no" && v != "accept-new" {
				issues = append(issues, Issue{
					HostName: h.Name,
					Severity: SeverityError,
					Rule:     "invalid-value",
					Message:  fmt.Sprintf("StrictHostKeyChecking %q — expected yes/no/accept-new", h.StrictHostKeyChecking),
					Line:     h.LineStart,
				})
			}
		}

		// ProxyJump loop: a host pointing at itself (directly or via alias
		// with the same name). Real ssh would hang connecting.
		if h.ProxyJump == h.Name {
			issues = append(issues, Issue{
				HostName: h.Name,
				Severity: SeverityError,
				Rule:     "proxyjump-loop",
				Message:  fmt.Sprintf("ProxyJump points at itself (%q)", h.ProxyJump),
				Line:     h.LineStart,
			})
		}

		// DevPod hosts are managed externally — skip further checks
		if h.Source == SourceDevPod {
			continue
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

// ValidateCertExpiry checks a certificate's validity window. Separated from
// Validate because it needs the current time injectable for tests.
func ValidateCertExpiry(c Certificate) (Issue, bool) {
	if c.IsExpired() {
		return Issue{
			HostName: c.Identity,
			Severity: SeverityWarning,
			Rule:     "cert-expired",
			Message:  fmt.Sprintf("certificate expired %s", c.ValidBefore.Format(time.RFC3339)),
		}, true
	}
	return Issue{}, false
}

// validatePort returns an error message if the port is invalid, "" if OK.
func validatePort(port string) string {
	port = strings.TrimSpace(port)
	// Allow "Port 22" style values; strip a leading colon if present.
	port = strings.TrimPrefix(port, ":")
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Sprintf("Port %q is not numeric", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Sprintf("Port %d out of range (1-65535)", n)
	}
	return ""
}

// isValidBoolean checks SSH boolean option values.
// StrictHostKeyChecking additionally accepts "accept-new".
func isValidBoolean(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "no":
		return true
	default:
		return false
	}
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
