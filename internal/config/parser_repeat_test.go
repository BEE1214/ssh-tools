package config

import (
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

func parseOne(t *testing.T, text string) domain.Host {
	t.Helper()
	cfg, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(cfg.Hosts))
	}
	return cfg.Hosts[0]
}

// ssh uses the FIRST value of a repeated scalar option.
func TestParse_RepeatedScalarFirstWins(t *testing.T) {
	h := parseOne(t, `Host web
  HostName 10.0.0.1
  HostName 10.0.0.2
  User first
  User second
  Port 2201
  Port 2202
  ProxyJump j1.example.com
  ProxyJump j2.example.com
  StrictHostKeyChecking yes
  StrictHostKeyChecking no
  ServerAliveInterval 30
  serveraliveinterval 60
  SendEnv LANG
  SendEnv LC_*
`)
	if h.HostName != "10.0.0.1" || h.User != "first" || h.Port != "2201" ||
		h.ProxyJump != "j1.example.com" || h.StrictHostKeyChecking != "yes" {
		t.Errorf("scalars not first-wins: %+v", h)
	}
	if got := h.Extra["ServerAliveInterval"]; got != "30" || len(h.Extra) != 2 {
		t.Errorf("repeated unknown key: Extra = %v, want ServerAliveInterval=30 only (plus SendEnv)", h.Extra)
	}
	if h.Extra["SendEnv"] != "LANG LC_*" {
		t.Errorf("SendEnv = %q, want accumulated %q", h.Extra["SendEnv"], "LANG LC_*")
	}
}

func TestParse_RepeatedIdentityAndCertificateFilesKeptInOrder(t *testing.T) {
	h := parseOne(t, `Host web
  IdentityFile ~/.ssh/a
  CertificateFile ~/.ssh/a-cert.pub
  IdentityFile ~/.ssh/b
  IdentityFile ~/.ssh/c
  CertificateFile ~/.ssh/b-cert.pub
`)
	if want := []string{"~/.ssh/a", "~/.ssh/b", "~/.ssh/c"}; !reflect.DeepEqual(h.IdentityFiles, want) {
		t.Errorf("IdentityFiles = %v, want %v", h.IdentityFiles, want)
	}
	if want := []string{"~/.ssh/a-cert.pub", "~/.ssh/b-cert.pub"}; !reflect.DeepEqual(h.CertificateFiles, want) {
		t.Errorf("CertificateFiles = %v, want %v", h.CertificateFiles, want)
	}
	if h.IdentityFile != "~/.ssh/a" || h.CertificateFile != "~/.ssh/a-cert.pub" {
		t.Errorf("singular fields must be the FIRST value, got %q / %q", h.IdentityFile, h.CertificateFile)
	}
}

func TestParse_KeyEqualsValueForms(t *testing.T) {
	h := parseOne(t, "Host=web\n"+
		"  HostName=10.0.0.1\n"+
		"  User = alice\n"+
		"  Port =2222\n"+
		"  IdentityFile= ~/.ssh/k\n"+
		"  ProxyCommand ssh -W %h:%p jump x=y\n"+
		"  Compression=yes\n"+
		"  LocalForward=8080 localhost:80\n")
	if h.Name != "web" || h.HostName != "10.0.0.1" || h.User != "alice" || h.Port != "2222" || h.IdentityFile != "~/.ssh/k" {
		t.Errorf("Key=value forms not parsed: %+v", h)
	}
	if h.ProxyCommand != "ssh -W %h:%p jump x=y" {
		t.Errorf("a '=' inside the value must be kept, got %q", h.ProxyCommand)
	}
	if h.Extra["Compression"] != "yes" {
		t.Errorf("Extra = %v", h.Extra)
	}
	if !reflect.DeepEqual(h.LocalForwards, []string{"8080 localhost:80"}) {
		t.Errorf("LocalForwards = %v", h.LocalForwards)
	}
}

func TestParse_HostLineVariants(t *testing.T) {
	cfg, err := Parse([]byte("Host\ttab\n  User a\n\nhost lower\n  User b\n\nHost = eq\n  User c\n\nHostName not-a-host\n"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, h := range cfg.Hosts {
		names = append(names, h.Name)
	}
	if want := []string{"tab", "lower", "eq"}; !reflect.DeepEqual(names, want) {
		t.Errorf("host names = %v, want %v", names, want)
	}
}

// blockText renders h with BlockLines, the canonical block of a new host.
func blockText(t *testing.T, h domain.Host) string {
	t.Helper()
	lines, err := BlockLines(h)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n") + "\n"
}

// An explicit "Port 22" must be written: dropping it would make the host fall
// through to a later "Host * / Port 2200".
func TestBlockLines_Port22IsWritten(t *testing.T) {
	in := "Host web\n  HostName 10.0.0.1\n  Port 22\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := blockText(t, cfg.Hosts[0]); got != in {
		t.Errorf("BlockLines changed the block:\n got %q\nwant %q", got, in)
	}
}

func TestBlockLines_EmitsAllIdentityAndCertificateFiles(t *testing.T) {
	in := "Host web\n  IdentityFile ~/.ssh/a\n  IdentityFile ~/.ssh/b\n  CertificateFile ~/.ssh/a-cert.pub\n  CertificateFile ~/.ssh/b-cert.pub\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := blockText(t, cfg.Hosts[0]); got != in {
		t.Errorf("BlockLines lost repeated lines:\n got %q\nwant %q", got, in)
	}
}

// Consumers that only know the singular fields keep working: the singular
// value replaces the first list entry, an empty singular value clears
// nothing by itself (callers clear the list too, see app.applyChange).
func TestBlockLines_SingularFieldOverridesFirstListEntry(t *testing.T) {
	cfg, err := Parse([]byte("Host web\n  IdentityFile ~/.ssh/a\n  IdentityFile ~/.ssh/b\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hosts[0].IdentityFile = "~/.ssh/new"
	if got, want := blockText(t, cfg.Hosts[0]), "Host web\n  IdentityFile ~/.ssh/new\n  IdentityFile ~/.ssh/b\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// Host built without lists (init, tests): singular field only.
	got := blockText(t, domain.Host{Name: "h", IdentityFile: "~/.ssh/k", CertificateFile: "~/.ssh/k-cert.pub"})
	if want := "Host h\n  IdentityFile ~/.ssh/k\n  CertificateFile ~/.ssh/k-cert.pub\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBlockLines_RefusesLineBreakInListValues(t *testing.T) {
	_, err := BlockLines(domain.Host{Name: "h", IdentityFiles: []string{"a", "b\nProxyCommand evil"}})
	if err == nil {
		t.Fatal("BlockLines accepted a line break in IdentityFiles")
	}
}

func TestDifferential_RepeatedKeysAgainstSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}
	dir := t.TempDir()
	cfgPath := write(t, filepath.Join(dir, "config"), strings.ReplaceAll(`Host rep
  HostName 10.0.0.1
  HostName 10.0.0.9
  User=first
  User second
  Port 22
  Port 2299
  IdentityFile @@/id_a
  IdentityFile = @@/id_b
  CertificateFile @@/id_a-cert.pub
  CertificateFile @@/id_b-cert.pub

Host *
  Port 2200
  User star
  IdentityFile @@/id_star
  CertificateFile @@/star-cert.pub
`, "@@", dir))

	l, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := domain.EffectiveConfig(l.Hosts, "rep")
	if err != nil {
		t.Fatal(err)
	}
	ssh := sshG(t, cfgPath, "rep")
	if got, want := mine.HostName, first(ssh["hostname"]); got != want {
		t.Errorf("hostname: sshm %q, ssh %q", got, want)
	}
	if got, want := mine.User, first(ssh["user"]); got != want {
		t.Errorf("user: sshm %q, ssh %q", got, want)
	}
	if got, want := mine.Port, first(ssh["port"]); got != want {
		t.Errorf("port: sshm %q, ssh %q (explicit Port 22 beats Host *)", got, want)
	}
	assertSetEqual(t, "identityfile", mine.IdentityFiles, ssh["identityfile"])
	assertSetEqual(t, "certificatefile", mine.CertificateFiles, ssh["certificatefile"])
	if len(mine.IdentityFiles) != 3 {
		t.Errorf("IdentityFiles = %v, want 3 accumulated values", mine.IdentityFiles)
	}
}
