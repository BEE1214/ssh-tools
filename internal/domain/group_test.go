package domain

import (
	"testing"
)

func TestGroupFor(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"host-acq-dev", "host"},
		{"host-acq-local", "host"},
		{"host-dev-plc", "host"},
		{"zf-poland3-mgmt", "zf"},
		{"zf-poland1-svs", "zf"},
		{"zf-poland1-pve", "zf"},
		{"gpu-cluster-node-white", "gpu"},
		{"karel-pve-proxy", "karel"},
		{"karel-mgmt-local", "karel"},
		{"emil", ""},
		{"jefry", ""},
		{"cooper2-local", "cooper2"},
		{"cooper2", ""},
		{"nas-home", "nas"},
		{"", ""},
		{"sda", ""},
		{"sda-local", "sda"},
		{"sda-root-local", "sda"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GroupFor(tt.name)
			if got != tt.want {
				t.Errorf("GroupFor(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestGroupHosts(t *testing.T) {
	hosts := []Host{
		{Name: "host-acq-dev", Group: "host"},
		{Name: "host-router", Group: "host"},
		{Name: "emil", Group: ""},
		{Name: "jefry", Group: ""},
	}
	groups := GroupHosts(hosts)

	if len(groups["host"]) != 2 {
		t.Errorf("host group: got %d hosts, want 2", len(groups["host"]))
	}
	if len(groups["ungrouped"]) != 2 {
		t.Errorf("ungrouped: got %d hosts, want 2", len(groups["ungrouped"]))
	}
}

func TestGroupNames(t *testing.T) {
	groups := map[string][]Host{
		"ungrouped": {{Name: "emil"}},
		"host":      {{Name: "host-1"}},
		"zf-poland": {{Name: "zf-poland1"}},
	}
	names := GroupNames(groups)

	// Should be sorted alphabetically with "ungrouped" last.
	if len(names) != 3 {
		t.Fatalf("got %d names, want 3", len(names))
	}
	if names[0] != "host" {
		t.Errorf("names[0] = %q, want %q", names[0], "host")
	}
	if names[2] != "ungrouped" {
		t.Errorf("names[2] = %q, want %q", names[2], "ungrouped")
	}
}
