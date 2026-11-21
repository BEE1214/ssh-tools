package cli

// P7 clause N2 at the CLI (PLAN-p7.md): the commands find `Host web-1 # prod`
// by the name a user types. The App-level and parser-level clauses are in
// internal/app/hostname_test.go and internal/config/hostname_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hnManaged = cliManagedHeader + `
Host web-1 # prod
  HostName 10.0.0.1
  User alice
  IdentityFile @D@/keys/web1
  CertificateFile @D@/keys/web1-cert.pub
  LocalForward 8080 localhost:80

Host sign-1 # prod
  HostName 10.0.0.4
  User carol
  IdentityFile @D@/keys/sign1
`

func hnNew(t *testing.T) *cliEnv { t.Helper(); return nsNew(t, nsSetUpMain, hnManaged) }

// dump finds the host (red now: the raw argument text "web-1 # prod" is the name).
func TestHostNameCommentCLI_Dump(t *testing.T) {
	hnNew(t)
	stdout, stderr, err := runCLI(t, "dump", "web-1")
	if err != nil {
		t.Fatalf("dump web-1: %v\n%s", err, stderr)
	}
	for _, want := range []string{"HostName 10.0.0.1", "User alice"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("dump web-1 lacks %q:\n%s", want, stdout)
		}
	}
}

// connect: the host is found, so the command goes on to ssh (stopped at "ssh not
// found", PATH is empty) instead of "host not found".
func TestHostNameCommentCLI_ConnectAndForwardFindTheHost(t *testing.T) {
	hnNew(t)
	nsEmptyPath(t)
	for name, args := range map[string][]string{
		"sshm web-1":         {"web-1"},
		"connect web-1":      {"connect", "web-1"},
		"forward web-1 spec": {"forward", "web-1", "9090:localhost:90"},
	} {
		_, _, err := runCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), "ssh not found in PATH") {
			t.Errorf("%s: error %v, want the 'ssh not found in PATH' stop (the host was found)", name, err)
		}
	}
}

// copy and connect refuse a host of a disabled group by its typed name.
func TestHostNameCommentCLI_DisabledGroupGatesConnectAndCopy(t *testing.T) {
	e := hnNew(t)
	e.write(t, e.managed+".sshm-groups", "# sshm group state\nweb\n")
	nsEmptyPath(t)
	for name, args := range map[string][]string{
		"connect": {"connect", "web-1"},
		"copy":    {"copy", "web-1:/tmp/x", filepath.Join(e.dir, "x")},
	} {
		_, _, err := runCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), `is in disabled group "web"`) {
			t.Errorf("%s web-1: error %v, want the disabled-group refusal", name, err)
		}
	}
}

// forward --list and --clear find the host.
func TestHostNameCommentCLI_ForwardListAndClear(t *testing.T) {
	e := hnNew(t)
	stdout, stderr, err := runCLI(t, "forward", "--list", "web-1")
	if err != nil || !strings.Contains(stdout, "LocalForward 8080 localhost:80") {
		t.Errorf("forward --list web-1: err %v, stdout %q, stderr %q; want the saved forward", err, stdout, stderr)
	}
	if _, stderr, err = runCLI(t, "forward", "--clear", "web-1"); err != nil {
		t.Fatalf("forward --clear web-1: %v\n%s", err, stderr)
	}
	if strings.Contains(e.readManaged(t), "LocalForward") {
		t.Errorf("forward not cleared:\n%s", e.readManaged(t))
	}
}

// edit finds the host (green now) and keeps the comment on the Host line.
func TestHostNameCommentCLI_Edit(t *testing.T) {
	e := hnNew(t)
	stdout, stderr, err := runCLI(t, "edit", "web-1", "--user", "zed")
	if err != nil || !strings.Contains(stdout, "Updated host web-1") {
		t.Fatalf("edit web-1: err %v, stdout %q, stderr %q", err, stdout, stderr)
	}
	if got := e.readManaged(t); !strings.Contains(got, "Host web-1 # prod\n  HostName 10.0.0.1\n  User zed\n") {
		t.Errorf("the block was not edited in place:\n%s", got)
	}
}

// cert sign with a host (red now: SignCert looks the raw name up) and cert revoke
// (red now: the CertificateFile line is looked up by the raw name and stays
// behind while the certificate file is deleted).
func TestHostNameCommentCLI_Cert(t *testing.T) {
	e := hnNew(t)
	nsFakeKeygen(t)
	cert := filepath.Join(e.dir, "keys", "sign1-cert.pub")
	_, stderr, err := runCLI(t, "cert", "sign", "sign-1", "--ca-key", filepath.Join(e.dir, "keys", "ca"))
	if err != nil {
		t.Fatalf("cert sign sign-1: %v\n%s", err, stderr)
	}
	if !strings.Contains(e.readManaged(t), "CertificateFile "+cert) {
		t.Errorf("CertificateFile not recorded:\n%s", e.readManaged(t))
	}

	web := filepath.Join(e.dir, "keys", "web1-cert.pub")
	if _, stderr, err = runCLI(t, "cert", "revoke", web); err != nil {
		t.Fatalf("cert revoke: %v\n%s", err, stderr)
	}
	if _, serr := os.Stat(web); serr == nil {
		t.Error("the certificate file was not deleted")
	}
	if got := e.readManaged(t); strings.Contains(got, "CertificateFile "+web) {
		t.Errorf("revoke left the CertificateFile line of web-1:\n%s", got)
	}
}
