package domain

import (
	"fmt"
	"strings"
)

// GroupFor derives a group name from a host name by taking the first segment
// before a dash. This is intentionally simple and predictable.
//
// Examples:
//
//	host-acq-dev   -> host
//	zf-poland3-mgmt -> zf
//	karel-pve-proxy -> karel
//	emil            -> "" (ungrouped)
//	cooper2-local   -> cooper2
//	nas-home        -> nas
//
// For more precise grouping, use an explicit "# group: <name>" comment
// above the Host line in the config file (honored by the config parser).
func GroupFor(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) <= 1 {
		return ""
	}
	return parts[0]
}

// GroupHosts groups hosts by their detected group name.
// Hosts with no group ("") are placed under the "ungrouped" key.
func GroupHosts(hosts []Host) map[string][]Host {
	result := make(map[string][]Host)
	for _, h := range hosts {
		g := h.Group
		if g == "" {
			g = "ungrouped"
		}
		result[g] = append(result[g], h)
	}
	return result
}

// GroupNames returns sorted group names from a GroupHosts result,
// with "ungrouped" always last.
func GroupNames(groups map[string][]Host) []string {
	var names []string
	hasUngrouped := false
	for name := range groups {
		if name == "ungrouped" {
			hasUngrouped = true
			continue
		}
		names = append(names, name)
	}
	sortStrings(names)
	if hasUngrouped {
		names = append(names, "ungrouped")
	}
	return names
}

// GroupCommentPrefix is the "# group:" comment prefix honored by the parser
// as an explicit group assignment above a Host line.
const GroupCommentPrefix = "# group:"

// GroupFromComment returns the group name from a "# group: <name>" comment
// line, or ("", false) if the line is not a group comment.
func GroupFromComment(line string) (string, bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, GroupCommentPrefix) {
		return "", false
	}
	name := strings.TrimSpace(s[len(GroupCommentPrefix):])
	if name == "" {
		return "", false
	}
	return name, true
}

// ValidateGroupName checks a user-supplied group name against the marker
// format. Group names must not be empty or contain whitespace or '#'.
func ValidateGroupName(name string) error {
	if name == "" {
		return fmt.Errorf("group name must not be empty")
	}
	if strings.ContainsAny(name, " \t#") {
		return fmt.Errorf("group name %q must not contain whitespace or '#'", name)
	}
	return nil
}

// DisabledMarkerStart returns the exact comment marker that opens a disabled
// group block. The marker pair is the boundary of the disabled section: the
// enable operation only scans between start and end markers, never beyond,
// so comments inside the block survive an enable cycle.
func DisabledMarkerStart(group string) string {
	return fmt.Sprintf("# sshm disabled group=%s start", group)
}

// DisabledMarkerEnd returns the exact comment marker that closes a disabled
// group's block. Repeated disable/enable cycles each leave one pair.
func DisabledMarkerEnd(group string) string {
	return fmt.Sprintf("# sshm disabled group=%s end", group)
}

// IsDisabledMarkerStart checks whether a comment line is the start marker of
// a disabled group block and, if so, returns the group name.
func IsDisabledMarkerStart(line string) (string, bool) {
	return markerGroup(line, " start")
}

// IsDisabledMarkerEnd checks whether a comment line is the end marker of a
// disabled group block and, if so, returns the group name.
func IsDisabledMarkerEnd(line string) (string, bool) {
	return markerGroup(line, " end")
}

// markerGroup parses "# sshm disabled group=<name> <suffix>" comment lines.
func markerGroup(line, suffix string) (string, bool) {
	const prefix = "# sshm disabled group="
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	rest := s[len(prefix):]
	if !strings.HasSuffix(rest, suffix) {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimSuffix(rest, suffix))
	if name == "" {
		return "", false
	}
	return name, true
}

func sortStrings(s []string) {
	// Simple insertion sort — group counts are small.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}