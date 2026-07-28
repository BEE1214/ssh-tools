package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

func loadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParse_Basic(t *testing.T) {
	raw := loadTestdata(t, "basic.config")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}

	emil := cfg.Hosts[0]
	if emil.Name != "emil" {
		t.Errorf("Hosts[0].Name = %q, want emil", emil.Name)
	}
	if emil.HostName != "10.0.0.1" {
		t.Errorf("HostName = %q", emil.HostName)
	}
	if emil.User != "adam" {
		t.Errorf("User = %q", emil.User)
	}
	if emil.Port != "22" {
		t.Errorf("Port = %q, want 22", emil.Port)
	}
	if emil.IdentityFile != "~/.ssh/id_ed25519" {
		t.Errorf("IdentityFile = %q", emil.IdentityFile)
	}
}

func TestParse_DevPod(t *testing.T) {
	raw := loadTestdata(t, "devpod.config")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}

	devpod := cfg.Hosts[0]
	if devpod.Name != "opcuaclientpython.devpod" {
		t.Errorf("Name = %q", devpod.Name)
	}
	if devpod.Source != domain.SourceDevPod {
		t.Errorf("Source = %d, want %d (SourceDevPod)", devpod.Source, domain.SourceDevPod)
	}
	if devpod.ForwardAgent != "yes" {
		t.Errorf("ForwardAgent = %q", devpod.ForwardAgent)
	}
	if devpod.ProxyCommand == "" {
		t.Error("ProxyCommand should be set")
	}
}

func TestParse_MixedCase(t *testing.T) {
	raw := loadTestdata(t, "mixed_case.config")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}

	emil := cfg.Hosts[0]
	if emil.User != "adam" {
		t.Errorf("User = %q, want adam (case-insensitive parse)", emil.User)
	}
	if emil.IdentityFile != "~/.ssh/id_ed25519" {
		t.Errorf("IdentityFile = %q", emil.IdentityFile)
	}

	jefry := cfg.Hosts[1]
	if jefry.HostName != "10.0.0.2" {
		t.Errorf("HostName = %q (case-insensitive parse)", jefry.HostName)
	}
}

func TestParse_Wildcard(t *testing.T) {
	raw := loadTestdata(t, "wildcard.config")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}

	wildcard := cfg.Hosts[0]
	if !wildcard.IsWildcard() {
		t.Error("first host should be wildcard")
	}
	if wildcard.Extra["ServerAliveInterval"] != "60" {
		t.Errorf("ServerAliveInterval = %q, want 60", wildcard.Extra["ServerAliveInterval"])
	}
}

func TestParse_Duplicates(t *testing.T) {
	raw := loadTestdata(t, "duplicates.config")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}

	if cfg.Hosts[0].Name != "emil" || cfg.Hosts[1].Name != "emil" {
		t.Error("both hosts should be named emil")
	}
}

func TestRoundTrip_Basic(t *testing.T) {
	raw := loadTestdata(t, "basic.config")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the output again and compare.
	written, err := Write(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg2, err := Parse(written)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg2.Hosts) != len(cfg.Hosts) {
		t.Fatalf("host count changed: %d -> %d", len(cfg.Hosts), len(cfg2.Hosts))
	}

	for i, h := range cfg.Hosts {
		h2 := cfg2.Hosts[i]
		if h.Name != h2.Name {
			t.Errorf("host %d: Name %q != %q", i, h.Name, h2.Name)
		}
		if h.HostName != h2.HostName {
			t.Errorf("host %d: HostName %q != %q", i, h.HostName, h2.HostName)
		}
		if h.User != h2.User {
			t.Errorf("host %d: User %q != %q", i, h.User, h2.User)
		}
		if h.IdentityFile != h2.IdentityFile {
			t.Errorf("host %d: IdentityFile %q != %q", i, h.IdentityFile, h2.IdentityFile)
		}
	}
}

func TestRoundTrip_Wildcard(t *testing.T) {
	raw := loadTestdata(t, "wildcard.config")
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	written, err := Write(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg2, err := Parse(written)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg2.Hosts) != 2 {
		t.Fatalf("got %d hosts after round-trip, want 2", len(cfg2.Hosts))
	}

	if !cfg2.Hosts[0].IsWildcard() {
		t.Error("first host should still be wildcard after round-trip")
	}
}

func TestIsHostLine(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"Host emil", true},
		{"host emil", true},
		{"HOST emil", true},
		{"HostName 10.0.0.1", false},
		{"hostname 10.0.0.1", false},
		{"HostKeyAlgorithms ssh-ed25519", false},
		{"Host *", true},
		{"Host host-* zf-*", true},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := isHostLine(tt.line)
			if got != tt.want {
				t.Errorf("isHostLine(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}