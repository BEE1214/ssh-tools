package domain

import (
	"testing"
)

func TestEffectiveConfig_ExactMatch(t *testing.T) {
	hosts := []Host{
		{Name: "*", User: "default-user", Port: "22"},
		{Name: "emil", HostName: "10.0.0.1", User: "adam", IdentityFile: "~/.ssh/id_ed25519"},
	}
	result, err := EffectiveConfig(hosts, "emil")
	if err != nil {
		t.Fatal(err)
	}
	if result.HostName != "10.0.0.1" {
		t.Errorf("HostName = %q, want 10.0.0.1", result.HostName)
	}
	if result.User != "adam" {
		t.Errorf("User = %q, want adam", result.User)
	}
	// Port inherited from Host *
	if result.Port != "22" {
		t.Errorf("Port = %q, want 22", result.Port)
	}
}

func TestEffectiveConfig_WildcardOnly(t *testing.T) {
	hosts := []Host{
		{Name: "*", User: "default-user", Port: "2222"},
	}
	result, err := EffectiveConfig(hosts, "anyhost")
	if err != nil {
		t.Fatal(err)
	}
	if result.User != "default-user" {
		t.Errorf("User = %q, want default-user", result.User)
	}
}

func TestEffectiveConfig_NotFound(t *testing.T) {
	hosts := []Host{
		{Name: "emil"},
	}
	_, err := EffectiveConfig(hosts, "nonexistent")
	if err != ErrHostNotFound {
		t.Errorf("err = %v, want ErrHostNotFound", err)
	}
}

func TestEffectiveConfig_OverrideOrder(t *testing.T) {
	// Later matching blocks should override earlier ones.
	hosts := []Host{
		{Name: "*", Port: "22"},
		{Name: "host-*", Port: "20008"},
		{Name: "host-acq-dev", User: "root"},
	}
	result, err := EffectiveConfig(hosts, "host-acq-dev")
	if err != nil {
		t.Fatal(err)
	}
	if result.Port != "20008" {
		t.Errorf("Port = %q, want 20008", result.Port)
	}
	if result.User != "root" {
		t.Errorf("User = %q, want root", result.User)
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "anything", true},
		{"emil", "emil", true},
		{"emil", "jefry", false},
		{"host-*", "host-acq-dev", true},
		{"host-*", "zf-poland1", false},
		{"host-* zf-*", "zf-poland1", true},
		{"host-* zf-*", "emil", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.name, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.name)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}
