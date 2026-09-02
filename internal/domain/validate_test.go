package domain

import (
	"strings"
	"testing"
	"time"
)

func findRule(issues []Issue, rule string) []Issue {
	var result []Issue
	for _, i := range issues {
		if i.Rule == rule {
			result = append(result, i)
		}
	}
	return result
}

func TestValidate_InvalidPort(t *testing.T) {
	tests := []struct {
		port    string
		wantErr bool
	}{
		{"22", false},
		{"65535", false},
		{"1", false},
		{"0", true},
		{"65536", true},
		{"-1", true},
		{"abc", true},
		{"22abc", true},
		{"", false}, // empty means default, not an error
	}
	for _, tt := range tests {
		hosts := []Host{{Name: "emil", LineStart: 1, Port: tt.port, IdentityFile: "~/.ssh/k"}}
		issues := Validate(hosts)
		got := len(findRule(issues, "invalid-port")) > 0
		if got != tt.wantErr {
			t.Errorf("Port %q: invalid-port=%v, want %v", tt.port, got, tt.wantErr)
		}
	}
}

func TestValidate_InvalidBoolean(t *testing.T) {
	hosts := []Host{
		{Name: "emil", LineStart: 1, IdentityFile: "~/.ssh/k", ForwardAgent: "maybe"},
	}
	issues := Validate(hosts)
	found := findRule(issues, "invalid-value")
	if len(found) != 1 {
		t.Fatalf("got %d invalid-value issues, want 1", len(found))
	}
	if !strings.Contains(found[0].Message, "ForwardAgent") {
		t.Errorf("message should mention ForwardAgent: %q", found[0].Message)
	}
}

func TestValidate_ValidBoolean(t *testing.T) {
	hosts := []Host{
		{Name: "emil", LineStart: 1, IdentityFile: "~/.ssh/k", ForwardAgent: "yes", ForwardX11: "no"},
	}
	issues := Validate(hosts)
	if got := len(findRule(issues, "invalid-value")); got != 0 {
		t.Errorf("got %d invalid-value issues, want 0", got)
	}
}

func TestValidate_ProxyJumpLoop(t *testing.T) {
	hosts := []Host{
		{Name: "emil", LineStart: 1, IdentityFile: "~/.ssh/k", ProxyJump: "emil"},
	}
	issues := Validate(hosts)
	if got := len(findRule(issues, "proxyjump-loop")); got != 1 {
		t.Fatalf("got %d proxyjump-loop issues, want 1", got)
	}
}

func TestValidate_ProxyJumpOtherHostOK(t *testing.T) {
	hosts := []Host{
		{Name: "emil", LineStart: 1, IdentityFile: "~/.ssh/k", ProxyJump: "jefry"},
	}
	issues := Validate(hosts)
	if got := len(findRule(issues, "proxyjump-loop")); got != 0 {
		t.Errorf("got %d proxyjump-loop issues, want 0", got)
	}
}

func TestValidate_DuplicateWildcard(t *testing.T) {
	hosts := []Host{
		{Name: "*", LineStart: 1},
		{Name: "emil", LineStart: 5},
		{Name: "*", LineStart: 10},
	}
	issues := Validate(hosts)
	if got := len(findRule(issues, "duplicate-wildcard")); got != 1 {
		t.Fatalf("got %d duplicate-wildcard issues, want 1", got)
	}
}

func TestValidate_CertSatisfiesIdentity(t *testing.T) {
	// Host with only CertificateFile should not trigger missing-identity.
	hosts := []Host{
		{Name: "emil", LineStart: 1, CertificateFile: "~/.ssh/key-cert.pub"},
	}
	issues := Validate(hosts)
	if got := len(findRule(issues, "missing-identity")); got != 0 {
		t.Errorf("got %d missing-identity issues, want 0 (CertificateFile satisfies)", got)
	}
}

func TestValidateCertExpiry_Expired(t *testing.T) {
	c := Certificate{
		Identity:    "emil",
		ValidBefore: time.Now().Add(-1 * time.Hour),
	}
	issue, expired := ValidateCertExpiry(c)
	if !expired {
		t.Fatal("expected expired")
	}
	if issue.Rule != "cert-expired" {
		t.Errorf("rule = %q, want cert-expired", issue.Rule)
	}
}

func TestValidateCertExpiry_Valid(t *testing.T) {
	c := Certificate{
		Identity:    "emil",
		ValidBefore: time.Now().Add(1 * time.Hour),
	}
	_, expired := ValidateCertExpiry(c)
	if expired {
		t.Fatal("expected not expired")
	}
}
