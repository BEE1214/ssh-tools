package domain

import "testing"

func TestFuzzyMatch_Empty(t *testing.T) {
	hosts := []Host{
		{Name: "emil"},
		{Name: "jefry"},
		{Name: "host-acq-dev"},
	}
	result := FuzzyMatch(hosts, "")
	if len(result) != 3 {
		t.Fatalf("got %d, want 3", len(result))
	}
	if result[0] != "emil" {
		t.Errorf("first = %q, want emil (alphabetical)", result[0])
	}
}

func TestFuzzyMatch_ExactPrefix(t *testing.T) {
	hosts := []Host{
		{Name: "host-acq-dev"},
		{Name: "host-plc-dev"},
		{Name: "emil"},
	}
	result := FuzzyMatch(hosts, "host")
	if len(result) != 2 {
		t.Fatalf("got %d, want 2", len(result))
	}
	if result[0] != "host-acq-dev" {
		t.Errorf("first = %q, want host-acq-dev", result[0])
	}
}

func TestFuzzyMatch_Subsequence(t *testing.T) {
	hosts := []Host{
		{Name: "host-acq-dev"},
		{Name: "zf-poland3-mgmt"},
	}
	// "had" matches "host-acq-dev" as a subsequence: h-o-s-t-a-c-q-d-e-v
	result := FuzzyMatch(hosts, "had")
	if len(result) != 1 {
		t.Fatalf("got %d, want 1", len(result))
	}
	if result[0] != "host-acq-dev" {
		t.Errorf("got %q, want host-acq-dev", result[0])
	}
}

func TestFuzzyMatch_NoMatch(t *testing.T) {
	hosts := []Host{
		{Name: "emil"},
		{Name: "jefry"},
	}
	result := FuzzyMatch(hosts, "zzz")
	if len(result) != 0 {
		t.Fatalf("got %d, want 0", len(result))
	}
}

func TestFuzzyMatch_CaseInsensitive(t *testing.T) {
	hosts := []Host{
		{Name: "Host-Acq-Dev"},
	}
	result := FuzzyMatch(hosts, "host")
	if len(result) != 1 {
		t.Fatalf("got %d, want 1", len(result))
	}
}

func TestFuzzyMatch_PrefixBeforeSubsequence(t *testing.T) {
	hosts := []Host{
		{Name: "zfer-prod"},  // fuzzy match "zfer" via subsequence
		{Name: "zf-poland3"}, // prefix match "zf"
	}
	result := FuzzyMatch(hosts, "zf")
	// zf-poland3 is a prefix match, should come first
	if result[0] != "zf-poland3" {
		t.Errorf("first = %q, want zf-poland3 (prefix match)", result[0])
	}
}

func TestFuzzyScore_ConsecutiveBonus(t *testing.T) {
	// "host" contiguous in "host-acq-dev" should score higher than scattered
	s1, _ := fuzzyScore("host-acq-dev", "host")
	s2, _ := fuzzyScore("h-o-s-t", "host")
	if s1 <= s2 {
		t.Errorf("contiguous score %d should be > scattered score %d", s1, s2)
	}
}
