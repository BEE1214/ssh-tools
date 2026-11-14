package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

func initEnv(t *testing.T, content string) (*App, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	writeTemp(t, path, content)
	return NewAppWithPath(path), path
}

func parseFile(t *testing.T, path string) *config.ConfigFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func hostNames(cfg *config.ConfigFile) []string {
	var names []string
	for _, h := range cfg.Hosts {
		names = append(names, h.Name)
	}
	return names
}

func TestInitDefaults_EmptyConfig(t *testing.T) {
	a, path := initEnv(t, "")
	note, err := a.InitDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if note != "" {
		t.Errorf("unexpected note %q", note)
	}
	cfg := parseFile(t, path)
	if got := hostNames(cfg); len(got) != 1 || got[0] != "*" {
		t.Fatalf("hosts = %v, want [*]", got)
	}
	if cfg.Hosts[0].StrictHostKeyChecking != "accept-new" {
		t.Errorf("StrictHostKeyChecking = %q", cfg.Hosts[0].StrictHostKeyChecking)
	}
}

func TestInitDefaults_AppendsAfterHosts(t *testing.T) {
	a, path := initEnv(t, "Host web1\n  HostName 10.0.0.1\n  User alice\n  StrictHostKeyChecking yes\n\nHost db1\n  HostName 10.0.0.2\n  User bob\n")
	note, err := a.InitDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if note != "" {
		t.Errorf("unexpected note %q", note)
	}
	cfg := parseFile(t, path)
	got := hostNames(cfg)
	if len(got) != 3 || got[0] != "web1" || got[1] != "db1" || got[2] != "*" {
		t.Fatalf("host order = %v, want [web1 db1 *]", got)
	}
	if h := cfg.Hosts[0]; h.HostName != "10.0.0.1" || h.User != "alice" || h.StrictHostKeyChecking != "yes" {
		t.Errorf("web1 changed: %+v", h)
	}
	if h := cfg.Hosts[1]; h.HostName != "10.0.0.2" || h.User != "bob" || h.StrictHostKeyChecking != "" {
		t.Errorf("db1 changed: %+v", h)
	}
}

func TestInitDefaults_ExistingWildcardUpdatedInPlace(t *testing.T) {
	// Host * deliberately first: it must stay where it is, be rewritten with the
	// defaults, and the user gets a note.
	a, path := initEnv(t, "Host *\n  ServerAliveInterval 5\n\nHost web1\n  HostName 10.0.0.1\n")
	note, err := a.InitDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "Host * is at line 1, before other hosts") || !strings.Contains(note, "Move it to the end") {
		t.Errorf("note = %q", note)
	}
	cfg := parseFile(t, path)
	got := hostNames(cfg)
	if len(got) != 2 || got[0] != "*" || got[1] != "web1" {
		t.Fatalf("host order = %v, want [* web1]", got)
	}
	if cfg.Hosts[0].StrictHostKeyChecking != "accept-new" || cfg.Hosts[0].Extra["ServerAliveInterval"] != "60" {
		t.Errorf("Host * not repaired: %+v", cfg.Hosts[0])
	}
}

func TestInitDefaults_ExistingWildcardLastNoNote(t *testing.T) {
	a, path := initEnv(t, "Host web1\n  HostName 10.0.0.1\n\nHost *\n  ServerAliveInterval 5\n")
	note, err := a.InitDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if note != "" {
		t.Errorf("unexpected note %q", note)
	}
	if got := hostNames(parseFile(t, path)); len(got) != 2 || got[1] != "*" {
		t.Errorf("host order = %v", got)
	}
}

func TestInitDefaults_RealSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}
	a, path := initEnv(t, "Host strict\n  HostName 10.0.0.1\n  StrictHostKeyChecking yes\n\nHost plain\n  HostName 10.0.0.2\n")
	if _, err := a.InitDefaults(); err != nil {
		t.Fatal(err)
	}
	// The FULL generated file is used as written: every algorithm line must be
	// accepted by the real ssh (see TestInitDefaults_GeneratedConfigAcceptedBySSH).
	g := func(host string) string {
		out, err := exec.Command("ssh", "-F", path, "-G", host).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G %s: %v\n%s", host, err, out)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "stricthostkeychecking "); ok {
				return v
			}
		}
		t.Fatalf("no stricthostkeychecking in ssh -G %s", host)
		return ""
	}
	if got := g("strict"); got != "true" && got != "yes" {
		t.Errorf("strict host: stricthostkeychecking = %q, want its own yes kept", got)
	}
	if got := g("plain"); got != "accept-new" {
		t.Errorf("plain host: stricthostkeychecking = %q, want accept-new", got)
	}
}
