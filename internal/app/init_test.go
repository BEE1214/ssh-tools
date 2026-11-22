package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

// initEnv writes content as the main file of a config that is not set up.
func initEnv(t *testing.T, content string) (*App, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	writeTemp(t, path, content)
	return NewAppWithPath(path), path
}

// initSetUpEnv builds a set-up config (init needs one): the main file is the
// Include line of an empty managed file, a blank line and content.
func initSetUpEnv(t *testing.T, content string) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	managed := filepath.Join(dir, "config.d", "sshm.conf")
	if err := os.Mkdir(filepath.Dir(managed), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, managed, mgManagedHeader)
	writeTemp(t, path, "Include "+managed+"\n\n"+content)
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
	a, path := initSetUpEnv(t, "")
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
	a, path := initSetUpEnv(t, "Host web1\n  HostName 10.0.0.1\n  User alice\n  StrictHostKeyChecking yes\n\nHost db1\n  HostName 10.0.0.2\n  User bob\n")
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

// An existing Host * is never rewritten or moved, wherever it stands; the note
// says where it is and nothing is written.
func TestInitDefaults_ExistingWildcardIsLeftAlone(t *testing.T) {
	for name, content := range map[string]string{
		"first":  "Host *\n  ServerAliveInterval 5\n\nHost web1\n  HostName 10.0.0.1\n",
		"last":   "Host web1\n  HostName 10.0.0.1\n\nHost *\n  ServerAliveInterval 5\n",
		"middle": "Host web1\n  HostName 10.0.0.1\n\nHost *\n  ServerAliveInterval 5\n\nHost db1\n  HostName 10.0.0.2\n",
	} {
		t.Run(name, func(t *testing.T) {
			a, path := initSetUpEnv(t, content)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			written, note, err := a.InitDefaultsReport()
			if err != nil {
				t.Fatal(err)
			}
			if written || !strings.Contains(note, "Host * is already defined at "+path+":") || !strings.Contains(note, "sshm does not rewrite it") {
				t.Errorf("written = %v, note = %q", written, note)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Errorf("the main file changed:\n%s", after)
			}
		})
	}
}

func TestInitDefaults_RealSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}
	a, path := initSetUpEnv(t, "Host strict\n  HostName 10.0.0.1\n  StrictHostKeyChecking yes\n\nHost plain\n  HostName 10.0.0.2\n")
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
