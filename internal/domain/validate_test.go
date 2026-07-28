package domain

import (
	"testing"
)

func TestValidate_MissingIdentity(t *testing.T) {
	hosts := []Host{
		{Name: "emil", LineStart: 1, IdentityFile: "~/.ssh/key"},
		{Name: "jefry", LineStart: 5},
	}
	issues := Validate(hosts)

	found := false
	for _, i := range issues {
		if i.Rule == "missing-identity" && i.HostName == "jefry" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing-identity warning for jefry")
	}

	// emil should not have a missing-identity warning
	for _, i := range issues {
		if i.Rule == "missing-identity" && i.HostName == "emil" {
			t.Error("emil should not have missing-identity warning")
		}
	}
}

func TestValidate_DuplicateHost(t *testing.T) {
	hosts := []Host{
		{Name: "emil", LineStart: 1},
		{Name: "emil", LineStart: 10},
	}
	issues := Validate(hosts)

	found := false
	for _, i := range issues {
		if i.Rule == "duplicate-host" {
			found = true
		}
	}
	if !found {
		t.Error("expected duplicate-host error")
	}
	if !HasErrors(issues) {
		t.Error("HasErrors should return true")
	}
}

func TestValidate_StrictNo(t *testing.T) {
	hosts := []Host{
		{Name: "emil", LineStart: 1, StrictHostKeyChecking: "no"},
		{Name: "jefry", LineStart: 5, StrictHostKeyChecking: "accept-new"},
	}
	issues := Validate(hosts)

	found := false
	for _, i := range issues {
		if i.Rule == "strict-no" && i.HostName == "emil" {
			found = true
		}
	}
	if !found {
		t.Error("expected strict-no warning for emil")
	}

	// jefry should not have it
	for _, i := range issues {
		if i.Rule == "strict-no" && i.HostName == "jefry" {
			t.Error("jefry should not have strict-no warning")
		}
	}
}

func TestValidate_WildcardSkipsIdentity(t *testing.T) {
	hosts := []Host{
		{Name: "*", LineStart: 1},
	}
	issues := Validate(hosts)
	for _, i := range issues {
		if i.Rule == "missing-identity" {
			t.Error("wildcard host should not trigger missing-identity")
		}
	}
}

func TestFilterByHost(t *testing.T) {
	issues := []Issue{
		{HostName: "emil", Rule: "missing-identity"},
		{HostName: "jefry", Rule: "strict-no"},
	}
	filtered := FilterByHost(issues, "emil")
	if len(filtered) != 1 {
		t.Fatalf("got %d, want 1", len(filtered))
	}
	if filtered[0].HostName != "emil" {
		t.Errorf("got %q, want emil", filtered[0].HostName)
	}
}