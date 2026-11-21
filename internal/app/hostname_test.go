package app

// P7 clauses N2 and N3 at the App level (PLAN-p7.md): hosts defined as
// `Host web-1 # prod` are found by the name a user types, by every command,
// without the Snapshot rewrite of the name. The CLI side is in
// internal/cli/hostname_test.go; the parser side in internal/config.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

const hnManaged = mgManagedHeader + `
Host web-1 # prod
  HostName 10.0.0.1
  User alice
  IdentityFile @D@/keys/web1
  CertificateFile @D@/keys/web1-cert.pub

Host sign-1 # prod
  HostName 10.0.0.4
  User carol
  IdentityFile @D@/keys/sign1

Host db-1 # data
  HostName 10.0.0.2
`

// hnNew: set-up config whose hosts all carry an inline comment.
func hnNew(t *testing.T) *mgEnv { t.Helper(); return nsNew(t, nsSetUpMain, hnManaged) }

// N2: Snapshot entries carry the clean name straight from the parser.
func TestHostNameComment_SnapshotEntryName(t *testing.T) {
	e := hnNew(t)
	got := nsEntry(t, e.a, "web-1")
	if got.HostName != "10.0.0.1" || got.ReadOnlyReason != "" {
		t.Errorf("entry web-1: HostName %q ReadOnlyReason %q, want 10.0.0.1 and empty", got.HostName, got.ReadOnlyReason)
	}
	for _, e2 := range []HostEntry{nsEntry(t, e.a, "sign-1"), nsEntry(t, e.a, "db-1")} {
		if strings.Contains(e2.Name, "#") {
			t.Errorf("entry name %q keeps the comment", e2.Name)
		}
	}
}

// N2: read paths find the host by its name.
func TestHostNameComment_ReadCommandsFindTheHost(t *testing.T) {
	e := hnNew(t)
	h, err := e.a.Dump("web-1")
	if err != nil || h.HostName != "10.0.0.1" || h.User != "alice" {
		t.Errorf("Dump(web-1) = HostName %q User %q, err %v; want 10.0.0.1, alice", h.HostName, h.User, err)
	}
	lf, err := e.a.ListForwards("web-1")
	if err != nil || lf.Name != "web-1" {
		t.Errorf("ListForwards(web-1) = Name %q, err %v", lf.Name, err)
	}
	if err := e.a.CheckHostName("web-1"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("CheckHostName(web-1) = %v, want 'already exists'", err)
	}
	if _, err := e.a.CheckEdit("web-1", map[string]string{"user": "x"}); err != nil {
		t.Errorf("CheckEdit(web-1): %v", err)
	}
}

// N2 for connect: the host exists, so Connect goes on to start ssh (stopped
// here at "ssh not found", PATH is empty); it must not say "host not found".
func TestHostNameComment_ConnectFindsTheHost(t *testing.T) {
	e := hnNew(t)
	nsEmptyPath(t)
	err := e.a.Connect("web-1", nil)
	if err == nil || !strings.Contains(err.Error(), "ssh not found in PATH") {
		t.Errorf("Connect(web-1) = %v, want the 'ssh not found in PATH' stop (the host was found)", err)
	}
	err = e.a.RunForward("web-1", domain.ForwardLocal, []string{"8080:localhost:80"}, false)
	if err == nil || !strings.Contains(err.Error(), "ssh not found in PATH") {
		t.Errorf("RunForward(web-1) = %v, want the 'ssh not found in PATH' stop", err)
	}
}

// N2 for connect and copy: a host of a disabled group is gated by its name, so
// `Host web-1 # prod` cannot be reached around the gate by being "not found".
// The sidecar is written by hand (group "web" is disabled).
func TestHostNameComment_DisabledGroupGatesConnectAndCopy(t *testing.T) {
	e := hnNew(t)
	mgWrite(t, e.managed+".sshm-groups", "# sshm group state\nweb\n", 0o600)
	nsEmptyPath(t)
	for name, err := range map[string]error{
		"Connect": e.a.Connect("web-1", nil),
		"Copy":    e.a.Copy("web-1:/tmp/x", filepath.Join(e.dir, "x"), "-a"),
	} {
		if err == nil || !strings.Contains(err.Error(), `is in disabled group "web"`) {
			t.Errorf("%s(web-1) = %v, want the disabled-group refusal", name, err)
		}
	}
}

// N2 for the write commands (green now for those that already went by hostKey).
func TestHostNameComment_WriteCommandsFindTheHost(t *testing.T) {
	t.Run("EditHost", func(t *testing.T) {
		e := hnNew(t)
		if err := e.a.EditHost("web-1", map[string]string{"user": "zed"}); err != nil {
			t.Fatalf("EditHost: %v", err)
		}
		if got := e.readManaged(t); !strings.Contains(got, "Host web-1 # prod\n  HostName 10.0.0.1\n  User zed\n") {
			t.Errorf("the block was not edited in place:\n%s", got)
		}
	})
	t.Run("DuplicateHost", func(t *testing.T) {
		e := hnNew(t)
		if err := e.a.DuplicateHost("web-1", "web-9"); err != nil {
			t.Fatalf("DuplicateHost: %v", err)
		}
		if got := nsEntry(t, e.a, "web-9"); got.HostName != "10.0.0.1" {
			t.Errorf("the copy web-9 has HostName %q, want the source's 10.0.0.1", got.HostName)
		}
		if got := e.readManaged(t); strings.Count(got, "Host web-1 # prod") != 1 {
			t.Errorf("the source block changed:\n%s", got)
		}
	})
	t.Run("DeleteHost", func(t *testing.T) {
		e := hnNew(t)
		if err := e.a.DeleteHost("db-1"); err != nil {
			t.Fatalf("DeleteHost: %v", err)
		}
		if got := e.readManaged(t); strings.Contains(got, "db-1") || !strings.Contains(got, "Host web-1 # prod") {
			t.Errorf("DeleteHost(db-1) removed the wrong thing or nothing:\n%s", got)
		}
	})
	t.Run("AddForward and ClearForwards", func(t *testing.T) {
		e := hnNew(t)
		if err := e.a.AddForward("web-1", domain.ForwardLocal, []string{"8080:localhost:80"}); err != nil {
			t.Fatalf("AddForward: %v", err)
		}
		lf, err := e.a.ListForwards("web-1")
		if err != nil || len(lf.LocalForwards) != 1 {
			t.Fatalf("ListForwards = %v, %v; want the saved forward", lf.LocalForwards, err)
		}
		if err := e.a.ClearForwards("web-1"); err != nil {
			t.Fatalf("ClearForwards: %v", err)
		}
		if strings.Contains(e.readManaged(t), "LocalForward") {
			t.Errorf("forward not cleared:\n%s", e.readManaged(t))
		}
	})
	t.Run("ClearCertificateFile", func(t *testing.T) {
		e := hnNew(t)
		if err := e.a.ClearCertificateFile("web-1"); err != nil {
			t.Fatalf("ClearCertificateFile: %v", err)
		}
		if strings.Contains(e.readManaged(t), "CertificateFile") {
			t.Errorf("CertificateFile not cleared:\n%s", e.readManaged(t))
		}
	})
	t.Run("RevokeCert", func(t *testing.T) {
		e := hnNew(t)
		cert := filepath.Join(e.dir, "keys", "web1-cert.pub")
		if err := e.a.RevokeCert(cert); err != nil {
			t.Fatalf("RevokeCert: %v", err)
		}
		if mgExists(cert) || strings.Contains(e.readManaged(t), "CertificateFile") {
			t.Errorf("revoke left the cert file or the CertificateFile line:\n%s", e.readManaged(t))
		}
	})
	t.Run("SignCert with a host", func(t *testing.T) {
		e := hnNew(t)
		nsFakeKeygen(t)
		got, err := e.a.SignCert(SignOpts{HostName: "sign-1", CAKey: filepath.Join(e.dir, "keys", "ca")})
		if err != nil {
			t.Fatalf("SignCert(sign-1): %v", err)
		}
		if !strings.Contains(e.readManaged(t), "CertificateFile "+got) {
			t.Errorf("CertificateFile not recorded:\n%s", e.readManaged(t))
		}
	})
	t.Run("AddHost refuses the existing name", func(t *testing.T) {
		e := hnNew(t)
		if err := e.a.AddHost(domain.Host{Name: "web-1", HostName: "10.9.9.9"}); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("AddHost(web-1) = %v, want 'already exists'", err)
		}
	})
}

// N2 in a config that is not set up: the name check of the TUI/CLI finds a host
// that has an inline comment (it did not, the raw argument text was compared).
func TestHostNameComment_CheckHostNameWhenNotSetUp(t *testing.T) {
	e := nsNew(t, "Host web-1 # prod\n  HostName 10.0.0.1\n", mgAbsent)
	if err := e.a.CheckHostName("web-1"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("CheckHostName(web-1) = %v, want 'already exists'", err)
	}
	if err := e.a.CheckHostName("web-2"); err != nil {
		t.Errorf("CheckHostName(web-2) = %v, want nil", err)
	}
}

// N3 (characterization, green now): `Host # c` keeps its current name and
// `Host a b` + `Host a` raise no duplicate-host in a validate run.
func TestHostNameComment_ValidateRun(t *testing.T) {
	e := nsNew(t, "Host a b\n  HostName 1.1.1.1\n\nHost a\n  HostName 2.2.2.2\n\nHost # c\n  HostName 3.3.3.3\n", mgAbsent)
	issues, err := e.a.Validate()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range issues {
		if i.Rule == "duplicate-host" {
			t.Errorf("duplicate-host for `Host a b` + `Host a`: %+v", i)
		}
	}
	names := map[string]bool{}
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range snap.Hosts {
		names[h.Name] = true
	}
	for _, want := range []string{"a b", "a", "# c"} {
		if !names[want] {
			t.Errorf("Snapshot lacks an entry named %q (have %v)", want, names)
		}
	}
}

// N1 / spec item 14 at the App level: `Host web-1 # prod` and `Host web-1` in ONE
// file are the same host to ssh, so a validate run reports a duplicate-host;
// `Host * # c` counts as the default `Host *`, so a second `Host *` in the file
// is a duplicate too.
func TestHostNameComment_ValidateRunDuplicatesWithComment(t *testing.T) {
	e := nsNew(t, "Host web-1 # prod\n  HostName 1.1.1.1\n\nHost web-1\n  HostName 2.2.2.2\n\nHost * # c\n  User d\n\nHost *\n  User e\n", mgAbsent)
	issues, err := e.a.Validate()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, i := range issues {
		if i.Rule == "duplicate-host" {
			got[i.HostName]++
		}
	}
	for _, name := range []string{"web-1", "*"} {
		if got[name] != 1 {
			t.Errorf("%d duplicate-host issues for %q, want 1 (all: %v)", got[name], name, got)
		}
	}
}

// N3: a trailing comment on a `Host *` line does not stop InitDefaults from
// seeing the wildcard block (the name is "*" now, so it is "already defined").
func TestHostNameComment_HostStarWithCommentCountsAsDefined(t *testing.T) {
	e := nsNew(t, "Include @M@\nInclude @D@/extra.conf\n\nHost * # more defaults\n  ServerAliveCountMax 3\n", nsSetUpManaged)
	before := e.readMain(t)
	written, note, err := e.a.InitDefaultsReport()
	if err != nil {
		t.Fatal(err)
	}
	if written || !strings.Contains(note, "Host * is already defined at ") {
		t.Errorf("written=%v note=%q, want nothing written and the 'already defined' note", written, note)
	}
	if e.readMain(t) != before {
		t.Errorf("the main file changed:\n%s", e.readMain(t))
	}
}
