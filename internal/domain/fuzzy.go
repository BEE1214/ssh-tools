package domain

import (
	"sort"
	"strings"
)

// FuzzyMatch returns host names from the list that fuzzy-match the query.
// Matching is case-insensitive, subsequence-based: each character in the
// query must appear in the host name in order, but not necessarily contiguously.
//
// Results are sorted by:
//  1. Exact prefix match (highest priority)
//  2. Contiguous substring match
//  3. Fuzzy subsequence match (tighter match = higher priority)
//
// If query is empty, all host names are returned alphabetically.
func FuzzyMatch(hosts []Host, query string) []string {
	if query == "" {
		return sortedHostNames(hosts)
	}

	query = strings.ToLower(query)

	type match struct {
		name   string
		score  int
		prefix bool
	}

	var matches []match
	for _, h := range hosts {
		lower := strings.ToLower(h.Name)
		score, ok := fuzzyScore(lower, query)
		if !ok {
			continue
		}
		matches = append(matches, match{
			name:   h.Name,
			score:  score,
			prefix: strings.HasPrefix(lower, query),
		})
	}

	sort.Slice(matches, func(i, j int) bool {
		// Prefix matches first.
		if matches[i].prefix != matches[j].prefix {
			return matches[i].prefix
		}
		// Then by score (higher = better).
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		// Then alphabetically.
		return matches[i].name < matches[j].name
	})

	result := make([]string, len(matches))
	for i, m := range matches {
		result[i] = m.name
	}
	return result
}

// fuzzyScore returns a match score and true if query is a subsequence of s.
// Higher score = tighter match. Returns false if no match.
func fuzzyScore(s, query string) (int, bool) {
	if len(query) == 0 {
		return 0, true
	}
	if len(query) > len(s) {
		return 0, false
	}

	score := 0
	si := 0
	consecutive := 0

	for qi := 0; qi < len(query); qi++ {
		found := false
		for si < len(s) {
			if s[si] == query[qi] {
				found = true
				consecutive++
				score += consecutive * 10 // consecutive chars score higher
				si++
				break
			}
			consecutive = 0
			si++
		}
		if !found {
			return 0, false
		}
	}

	// Bonus for matching early in the string.
	score += (len(s) - si) // shorter remaining = better

	return score, true
}

// sortedHostNames returns all host names sorted alphabetically.
func sortedHostNames(hosts []Host) []string {
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	sort.Strings(names)
	return names
}
