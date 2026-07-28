package domain

import (
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
// above the Host line in the config file. The TUI also allows reassigning.
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

func sortStrings(s []string) {
	// Simple insertion sort — group counts are small.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}