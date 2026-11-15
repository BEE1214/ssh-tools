package app

// Black-box tests for write routing in managed mode (PLAN-p3-p4.md section 4,
// clauses R1-R14). Expected bytes come from the public config.Doc API (the
// spec names Doc.AppendBlock / DuplicateBlock / DeleteBlock / AddOptionValue)
// or from literal text edits; resolution is checked with real `ssh -F -G`.
//
// RunForward replaces the process on success (syscall.Exec), so every test
// that calls it runs with an empty PATH: a refusal is observable, a success
// stops at "ssh not found" after the save.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

const rtMain = `Include @M@
Include @D@/extra.conf

# hand-written hosts
Host main-1
  HostName 10.0.0.9
  User mainuser
  LocalForward 7000 127.0.0.1:7000
  CertificateFile /keys/main-1-cert.pub

Host *
  User fallback
  Port 2200
`

const rtExtra = `Host inc-1
  HostName 10.0.0.70
  User incuser
  LocalForward 7100 127.0.0.1:7100
  CertificateFile /keys/inc-1-cert.pub
`

const rtManaged = `# Managed by sshm.
# Hosts below are edited in place.

# primary web host
Host web-1
    hostname 10.0.0.1
    User alice # keep this comment
    Port 2222
    # inner comment
    IdentityFile /keys/web1_a
    IdentityFile /keys/web1_b

Host web-2
  HostName 10.0.0.3
  CertificateFile /certs/a
  CertificateFile /certs/b
  LocalForward 9000 127.0.0.1:9000

Host db-1
	HostName 10.0.0.2
	User dbuser
	ProxyJump jump.example.com
	HostKeyAlias db-one

Host clr-1
  HostName 10.0.0.20
  User carol
  Port 2022
  ProxyJump jump.example.com
  HostKeyAlias clr-one
`

var rtHosts = []string{"web-1", "web-2", "db-1", "clr-1", "main-1", "inc-1"}

func newRtEnv(t *testing.T) *mgEnv { return newRtEnvWith(t, rtMain, rtManaged) }

func newRtEnvWith(t *testing.T, mainBody, managedBody string) *mgEnv {
	t.Helper()
	e := newMgEnv(t, mainBody, managedBody)
	mgWrite(t, e.extra(), rtExtra, 0o600)
	return e
}

func (e *mgEnv) extra() string { return filepath.Join(e.dir, "extra.conf") }

func rtDoc(t *testing.T, e *mgEnv) *config.Doc {
	t.Helper()
	return config.ParseDoc([]byte(e.readManaged(t)))
}

// rtOnlyManagedChanged: the managed file is the only changed file (backups may appear).
func rtOnlyManagedChanged(t *testing.T, e *mgEnv, before mgTree) {
	t.Helper()
	if d := mgDiff(before, e.snap(t), true); !reflect.DeepEqual(d, []string{"changed " + e.managed}) {
		t.Errorf("changed files = %v, want only the managed file (main file and others byte- and mtime-identical)", d)
	}
}

func rtDropKey(text, key string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), strings.ToLower(key)+" ") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func rtCountKey(text, key string) int {
	return strings.Count(text, "\n") - strings.Count(rtDropKey(text, key), "\n")
}

func rtUnmanaged(host, file string, canImport bool) string {
	return (&UnmanagedHostError{Host: host, File: file, CanImport: canImport}).Error()
}

// ---- fixed strings (characterization: already implemented by the skeleton) ----

func TestFixedErrorStrings(t *testing.T) {
	t.Parallel()
	if got, want := ErrNotSetUp.Error(), "sshm is not set up: run 'sshm setup' first"; got != want {
		t.Errorf("ErrNotSetUp = %q, want %q", got, want)
	}
	if got, want := rtUnmanaged("x", "/c/config", true), `host "x" is defined in /c/config, which sshm does not manage; run 'sshm import'`; got != want {
		t.Errorf("main-file wording = %q", got)
	}
	if got, want := rtUnmanaged("x", "/c/inc.conf", false), `host "x" is defined in /c/inc.conf (included), which sshm does not manage`; got != want {
		t.Errorf("included-file wording = %q", got)
	}
}

// ---- R1: legacy mode ------------------------------------------------------------

// Characterization: legacy mode already behaves this way. A managed file that
// exists but is not included must not attract any write.
func TestLegacyMode_WritesStayInTheMainFile(t *testing.T) {
	t.Parallel()
	const stray = mgManagedHeader + "Host stray-1\n  HostName 10.0.0.80\n"
	e := newMgEnv(t, groupFixture, stray)
	if active, err := e.a.ManagedActive(); err == nil && active {
		t.Fatal("ManagedActive = true for a main file without an Include")
	}
	managedBefore := e.snap(t)[e.managed]

	userOf := func(name string) string {
		hs, err := e.a.ListHosts("", true)
		mgRequireNoErr(t, err)
		for _, h := range hs {
			if h.Name == name {
				return h.User
			}
		}
		return "<missing>"
	}
	mgRequireNoErr(t, e.a.AddHost(domain.Host{Name: "new-1", HostName: "10.0.0.50", User: "newuser"}))
	if !strings.Contains(e.readMain(t), "Host new-1") {
		t.Errorf("AddHost did not write to the main file:\n%s", e.readMain(t))
	}
	mgRequireNoErr(t, e.a.EditHost("web-1", map[string]string{"user": "zed"}))
	if got := userOf("web-1"); got != "zed" {
		t.Errorf("EditHost: user = %q", got)
	}
	mgRequireNoErr(t, e.a.DuplicateHost("web-1", "web-3"))
	if got := userOf("web-3"); got != "zed" {
		t.Errorf("DuplicateHost: user of web-3 = %q", got)
	}
	mgRequireNoErr(t, e.a.DeleteHost("misc"))
	if strings.Contains(e.readMain(t), "Host misc") {
		t.Error("DeleteHost left the block in the main file")
	}
	mgRequireNoErr(t, e.a.AddForward("web-1", domain.ForwardLocal, []string{"8080:localhost:80"}))
	if !strings.Contains(e.readMain(t), "LocalForward") {
		t.Error("AddForward did not write the forward to the main file")
	}
	mgRequireNoErr(t, e.a.ClearForwards("web-1"))
	if strings.Contains(e.readMain(t), "LocalForward") {
		t.Error("ClearForwards left the forward in the main file")
	}
	mgRequireNoErr(t, e.a.DisableGroup("deploy"))
	if !strings.Contains(e.readMain(t), domain.DisabledMarkerStart("deploy")) {
		t.Error("DisableGroup did not write markers to the main file")
	}
	mgRequireNoErr(t, e.a.EnableGroup("deploy"))
	if strings.Contains(e.readMain(t), domain.DisabledMarkerStart("deploy")) {
		t.Error("EnableGroup left the markers in the main file")
	}
	_, err := e.a.InitDefaults()
	mgRequireNoErr(t, err)
	if !strings.Contains(e.readMain(t), "Host *") {
		t.Error("InitDefaults did not add Host * to the main file")
	}
	if after := e.snap(t)[e.managed]; after != managedBefore {
		t.Error("the not-included managed file was touched in legacy mode")
	}
	if mgExists(mgSidecar(e.managed)) {
		t.Error("a managed-mode sidecar was created in legacy mode")
	}
}

// ---- R14: hint -------------------------------------------------------------------

func TestSetupHint(t *testing.T) {
	t.Parallel()
	t.Run("legacy mode", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, sxMain, mgAbsent)
		want := "hint: run 'sshm setup' to keep sshm-managed hosts in " + e.managed
		if got := e.a.SetupHint(); got != want {
			t.Errorf("SetupHint = %q, want %q", got, want)
		}
	})
	t.Run("managed mode", func(t *testing.T) {
		t.Parallel()
		e := newRtEnv(t)
		if got := e.a.SetupHint(); got != "" {
			t.Errorf("SetupHint = %q, want empty in managed mode", got)
		}
	})
}

// ---- R2: add -----------------------------------------------------------------------

func TestAdd_AppendsCanonicalBlockToTheManagedFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	before := e.snap(t)
	h := domain.Host{Name: "new-1", HostName: "10.0.0.50", User: "newuser", Port: "2022", IdentityFile: "/keys/new1"}

	d := rtDoc(t, e)
	if err := d.AppendBlock(h); err != nil {
		t.Fatal(err)
	}
	want := string(d.Bytes())

	mgRequireNoErr(t, e.a.AddHost(h))
	if got := e.readManaged(t); got != want {
		t.Errorf("managed file:\n%s\nwant (Doc.AppendBlock):\n%s", got, want)
	}
	rtOnlyManagedChanged(t, e, before)
	out := mgSSHG(t, e.main, "new-1")
	for k, v := range map[string]string{"hostname": "10.0.0.50", "user": "newuser", "port": "2022", "identityfile": "/keys/new1"} {
		if got := mgVal(out, k); got != v {
			t.Errorf("ssh -G new-1 %s = %q, want %q", k, got, v)
		}
	}
}

func TestAdd_NameMustNotExistInAnyLoadedFile(t *testing.T) {
	t.Parallel()
	e := newRtEnv(t)
	// A real add first, so a legacy-mode refusal cannot satisfy this test by accident.
	mgRequireNoErr(t, e.a.AddHost(domain.Host{Name: "new-1", HostName: "10.0.0.50"}))
	if !strings.Contains(e.readManaged(t), "Host new-1") {
		t.Fatalf("add did not reach the managed file:\n%s", e.readManaged(t))
	}
	before := e.snap(t)
	for _, name := range []string{"main-1", "web-1", "inc-1", "new-1"} {
		err := e.a.AddHost(domain.Host{Name: name, HostName: "10.0.0.99"})
		mgRequireErr(t, err)
		if !strings.Contains(err.Error(), name) {
			t.Errorf("AddHost(%s) error %q does not name the host", name, err)
		}
		mgRequireUnchanged(t, before, e.snap(t))
	}
}

// ---- R3: edit ----------------------------------------------------------------------

func TestEdit_PatchesOnlyTheTargetedLines(t *testing.T) {
	t.Parallel()
	type edit struct {
		name, host string
		changes    map[string]string
		want       func(orig string) string
		check      func(t *testing.T, orig, got string)
		ssh        func(t *testing.T, out string)
	}
	val := func(key, want string) func(*testing.T, string) {
		return func(t *testing.T, out string) {
			t.Helper()
			if got := mgVal(out, key); got != want {
				t.Errorf("ssh -G %s = %q, want %q", key, got, want)
			}
		}
	}
	rep := func(old, new string) func(string) string {
		return func(orig string) string { return strings.Replace(orig, old, new, 1) }
	}
	edits := []edit{
		{name: "user keeps indent and inline comment", host: "web-1", changes: map[string]string{"user": "bob"},
			want: rep("    User alice # keep this comment", "    User bob # keep this comment"), ssh: val("user", "bob")},
		{name: "hostname keeps key casing", host: "web-1", changes: map[string]string{"hostname": "10.9.9.9"},
			want: rep("    hostname 10.0.0.1\n", "    hostname 10.9.9.9\n"), ssh: val("hostname", "10.9.9.9")},
		{name: "tab indentation kept", host: "db-1", changes: map[string]string{"user": "dbroot"},
			want: rep("\tUser dbuser\n", "\tUser dbroot\n"), ssh: val("user", "dbroot")},
		{name: "empty value unsets", host: "web-1", changes: map[string]string{"port": ""},
			want: rep("    Port 2222\n", ""), ssh: val("port", "2200")}, // falls through to Host * of the main file
		{name: "two keys at once", host: "web-1", changes: map[string]string{"user": "u2", "port": "2223"},
			want: func(o string) string {
				return strings.Replace(strings.Replace(o, "alice #", "u2 #", 1), "Port 2222", "Port 2223", 1)
			}, ssh: val("port", "2223")},
		{name: "identityfile replaces the whole list", host: "web-1", changes: map[string]string{"identityfile": "/keys/new"},
			check: func(t *testing.T, orig, got string) {
				if rtDropKey(orig, "IdentityFile") != rtDropKey(got, "IdentityFile") {
					t.Errorf("lines other than IdentityFile changed:\n%s", got)
				}
				if n := rtCountKey(got, "IdentityFile"); n != 1 || !strings.Contains(got, "IdentityFile /keys/new") {
					t.Errorf("want exactly one IdentityFile line (/keys/new), got %d:\n%s", n, got)
				}
			}, ssh: val("identityfile", "/keys/new")},
		{name: "certificatefile replaces the whole list", host: "web-2", changes: map[string]string{"certificatefile": "/certs/c"},
			check: func(t *testing.T, orig, got string) {
				if rtDropKey(orig, "CertificateFile") != rtDropKey(got, "CertificateFile") {
					t.Errorf("lines other than CertificateFile changed:\n%s", got)
				}
				if n := rtCountKey(got, "CertificateFile"); n != 1 || !strings.Contains(got, "CertificateFile /certs/c") {
					t.Errorf("want exactly one CertificateFile line (/certs/c), got %d:\n%s", n, got)
				}
			}, ssh: val("certificatefile", "/certs/c")},
		{name: "new key is added inside the block", host: "web-1", changes: map[string]string{"proxyjump": "hop.example.com"},
			check: func(t *testing.T, orig, got string) {
				var rest []string
				for _, l := range strings.Split(got, "\n") {
					if !strings.Contains(l, "hop.example.com") {
						rest = append(rest, l)
					}
				}
				if strings.Join(rest, "\n") != orig || strings.Count(got, "hop.example.com") != 1 {
					t.Errorf("more than the one new ProxyJump line changed:\n%s", got)
				}
				lines := strings.Split(got, "\n")
				host, next, pj := -1, -1, -1
				for i, l := range lines {
					switch {
					case l == "Host web-1":
						host = i
					case l == "Host web-2":
						next = i
					case strings.Contains(l, "hop.example.com"):
						pj = i
					}
				}
				if !(host < pj && pj < next) {
					t.Errorf("ProxyJump line at %d is not inside the web-1 block (%d..%d):\n%s", pj, host, next, got)
				}
			}, ssh: val("proxyjump", "hop.example.com")},
		{name: "empty identityfile removes the whole list", host: "web-1", changes: map[string]string{"identityfile": ""},
			want: func(o string) string { return rtDropKey(o, "IdentityFile") },
			ssh: func(t *testing.T, out string) {
				if got := mgVal(out, "identityfile"); strings.Contains(got, "/keys/web1") {
					t.Errorf("identityfile = %q, the old keys are still configured", got)
				}
			}},
	}
	for _, c := range edits {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newRtEnv(t)
			orig := e.readManaged(t)
			before := e.snap(t)
			var resolved map[string]string
			if mgRealSSH != "" {
				resolved = mgSSHAll(t, e.main, rtHosts)
			}
			mgRequireNoErr(t, e.a.EditHost(c.host, c.changes))
			got := e.readManaged(t)
			if c.want != nil && got != c.want(orig) {
				t.Errorf("managed file:\n%s\nwant:\n%s", got, c.want(orig))
			}
			if c.check != nil {
				c.check(t, orig, got)
			}
			rtOnlyManagedChanged(t, e, before)
			if m := mgMode(t, e.managed); m != 0o600 {
				t.Errorf("managed mode = %o, want 0600", m)
			}
			if mgRealSSH == "" {
				return
			}
			c.ssh(t, mgSSHG(t, e.main, c.host))
			for h, old := range resolved {
				if h != c.host && mgSSHG(t, e.main, h) != old {
					t.Errorf("ssh -G %s changed, only %s should differ", h, c.host)
				}
			}
		})
	}
}

// R3: "uses setPlan, so the value must show up in ssh -G". The User of web-9 is
// shadowed by the earlier `Host web-*` block, so changing it has no effect on
// what ssh resolves and the edit is refused / rolled back.
func TestEdit_AValueThatDoesNotShowUpInSSHIsNotKept(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	managed := mgManagedHeader + "\nHost web-*\n  User wild\n\nHost web-9\n  HostName 10.0.0.9\n  User x\n"
	e := newRtEnvWith(t, rtMain, managed)

	// Control: an edit that does show up is saved.
	mgRequireNoErr(t, e.a.EditHost("web-9", map[string]string{"hostname": "10.0.0.19"}))
	saved := e.readManaged(t)
	if !strings.Contains(saved, "10.0.0.19") {
		t.Fatalf("the control edit did not reach the managed file:\n%s", saved)
	}

	before := e.snap(t)
	err := e.a.EditHost("web-9", map[string]string{"user": "y"})
	mgRequireErr(t, err)
	mgRequireRestored(t, before, e.snap(t), e.managed)
	if got := e.readManaged(t); got != saved {
		t.Errorf("managed file not restored byte-for-byte:\n%s", got)
	}
	if got := mgVal(mgSSHG(t, e.main, "web-9"), "user"); got != "wild" {
		t.Errorf("ssh -G web-9 user = %q, want wild", got)
	}
}

// ---- R4: hosts outside the managed file ----------------------------------------------

func TestUnmanagedHosts_WriteCommandsRefuseAndChangeNothing(t *testing.T) {
	mgNoSSHOnPath(t) // RunForward would replace the process on success
	e := newRtEnv(t)
	ops := []struct {
		name string
		do   func(host string) error
	}{
		{"edit", func(h string) error { return e.a.EditHost(h, map[string]string{"user": "x"}) }},
		{"edit (unset)", func(h string) error { return e.a.EditHost(h, map[string]string{"user": ""}) }},
		{"delete", func(h string) error { return e.a.DeleteHost(h) }},
		{"duplicate", func(h string) error { return e.a.DuplicateHost(h, h+"-copy") }},
		{"forward --save (AddForward)", func(h string) error {
			return e.a.AddForward(h, domain.ForwardLocal, []string{"8080:localhost:80"})
		}},
		{"forward --save (RunForward)", func(h string) error {
			return e.a.RunForward(h, domain.ForwardLocal, []string{"8080:localhost:80"}, true)
		}},
		{"forward --clear", func(h string) error { return e.a.ClearForwards(h) }},
		{"cert clearing", func(h string) error { return e.a.ClearCertificateFile(h) }},
	}
	hosts := []struct {
		name, file string
		canImport  bool
	}{
		{"main-1", e.main, true},
		{"inc-1", e.extra(), false},
	}
	for _, h := range hosts {
		for _, op := range ops {
			t.Run(h.name+"/"+op.name, func(t *testing.T) {
				before := mgSnap(t, e.dir)
				err := op.do(h.name)
				mgRequireErr(t, err)
				var ume *UnmanagedHostError
				if !errors.As(err, &ume) {
					t.Fatalf("error %T %q is not an *UnmanagedHostError", err, err)
				}
				if ume.Host != h.name || ume.File != h.file || ume.CanImport != h.canImport {
					t.Errorf("UnmanagedHostError = %+v, want host %s, file %s, CanImport %v", *ume, h.name, h.file, h.canImport)
				}
				if got, want := err.Error(), rtUnmanaged(h.name, h.file, h.canImport); got != want {
					t.Errorf("message = %q, want %q", got, want)
				}
				mgRequireUnchanged(t, before, mgSnap(t, e.dir))
			})
		}
	}
}

// ---- R5: duplicate --------------------------------------------------------------------

func TestDuplicate_UsesDocDuplicateBlockOnTheManagedFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	before := e.snap(t)
	d := rtDoc(t, e)
	if err := d.DuplicateBlock("web-1", "web-3"); err != nil {
		t.Fatal(err)
	}
	mgRequireNoErr(t, e.a.DuplicateHost("web-1", "web-3"))
	if got, want := e.readManaged(t), string(d.Bytes()); got != want {
		t.Errorf("managed file:\n%s\nwant (Doc.DuplicateBlock):\n%s", got, want)
	}
	rtOnlyManagedChanged(t, e, before)
	out := mgSSHG(t, e.main, "web-3")
	if got := mgVal(out, "hostname"); got != "10.0.0.1" {
		t.Errorf("ssh -G web-3 hostname = %q", got)
	}
	if got := mgVal(out, "identityfile"); got != "/keys/web1_a,/keys/web1_b" {
		t.Errorf("ssh -G web-3 identityfile = %q", got)
	}

	// The new name must be new everywhere.
	after := e.snap(t)
	for _, name := range []string{"main-1", "db-1", "inc-1", "web-3"} {
		err := e.a.DuplicateHost("web-2", name)
		mgRequireErr(t, err)
		if !strings.Contains(err.Error(), name) {
			t.Errorf("DuplicateHost(web-2 -> %s): error %q does not name the host", name, err)
		}
		mgRequireUnchanged(t, after, e.snap(t))
	}
}

// ---- R6: delete -----------------------------------------------------------------------

func TestDelete_RemovesTheBlockFromTheManagedFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	before := e.snap(t)
	d := rtDoc(t, e)
	if err := d.DeleteBlock("db-1"); err != nil {
		t.Fatal(err)
	}
	web1 := mgSSHG(t, e.main, "web-1")
	mgRequireNoErr(t, e.a.DeleteHost("db-1"))
	if got, want := e.readManaged(t), string(d.Bytes()); got != want {
		t.Errorf("managed file:\n%s\nwant (Doc.DeleteBlock):\n%s", got, want)
	}
	rtOnlyManagedChanged(t, e, before)
	if got := mgVal(mgSSHG(t, e.main, "db-1"), "hostname"); got != "db-1" {
		t.Errorf("db-1 still resolves: hostname = %q", got)
	}
	if mgSSHG(t, e.main, "web-1") != web1 {
		t.Error("web-1 resolves differently after deleting db-1")
	}
}

// ---- R7: forwards ---------------------------------------------------------------------

func TestForwards_SaveAndClearUseTheManagedFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	orig := e.readManaged(t)
	before := e.snap(t)

	d := rtDoc(t, e)
	specs := []struct {
		kind domain.ForwardKind
		spec string
	}{
		{domain.ForwardLocal, "8080:localhost:80"},
		{domain.ForwardRemote, "9090:localhost:90"},
		{domain.ForwardDynamic, "1080"},
	}
	for _, s := range specs {
		canon, err := domain.ParseForwardSpec(s.kind, s.spec)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.AddOptionValue("web-1", s.kind.ConfigKey(), canon); err != nil {
			t.Fatal(err)
		}
		mgRequireNoErr(t, e.a.AddForward("web-1", s.kind, []string{s.spec}))
	}
	if got, want := e.readManaged(t), string(d.Bytes()); got != want {
		t.Errorf("managed file after AddForward:\n%s\nwant (Doc.AddOptionValue):\n%s", got, want)
	}
	rtOnlyManagedChanged(t, e, before)
	out := mgSSHG(t, e.main, "web-1")
	if mgVal(out, "localforward") == "" || mgVal(out, "remoteforward") == "" || mgVal(out, "dynamicforward") == "" {
		t.Errorf("ssh -G web-1 lacks a saved forward:\nlocal=%q remote=%q dynamic=%q", mgVal(out, "localforward"), mgVal(out, "remoteforward"), mgVal(out, "dynamicforward"))
	}

	// --clear removes every forward line again.
	mgRequireNoErr(t, e.a.ClearForwards("web-1"))
	if got := e.readManaged(t); got != orig {
		t.Errorf("managed file after ClearForwards:\n%s\nwant the original:\n%s", got, orig)
	}
	// ...including forwards that were there before sshm touched the host.
	mgRequireNoErr(t, e.a.ClearForwards("web-2"))
	if got, want := e.readManaged(t), strings.Replace(orig, "  LocalForward 9000 127.0.0.1:9000\n", "", 1); got != want {
		t.Errorf("managed file after ClearForwards(web-2):\n%s\nwant:\n%s", got, want)
	}
	if got := mgVal(mgSSHG(t, e.main, "web-2"), "localforward"); got != "" {
		t.Errorf("web-2 still forwards: %q", got)
	}
	rtOnlyManagedChanged(t, e, before)
}

// Characterization: forward without --save reads only. With ssh off PATH the
// run stops at "ssh not found", for managed and unmanaged hosts alike.
func TestForward_WithoutSaveWritesNothingAndWorksForAnyHost(t *testing.T) {
	mgNoSSHOnPath(t)
	e := newRtEnv(t)
	for _, host := range []string{"web-1", "main-1", "inc-1"} {
		before := e.snap(t)
		err := e.a.RunForward(host, domain.ForwardLocal, []string{"8080:localhost:80"}, false)
		mgRequireErr(t, err)
		var ume *UnmanagedHostError
		if errors.As(err, &ume) {
			t.Errorf("%s: forward without --save was refused as unmanaged: %v", host, err)
		}
		if !strings.Contains(err.Error(), "ssh not found") {
			t.Errorf("%s: err = %v, want the ssh-not-found stop", host, err)
		}
		mgRequireUnchanged(t, before, e.snap(t))
	}
	h, err := e.a.ListForwards("main-1")
	mgRequireNoErr(t, err)
	if len(h.LocalForwards) != 1 {
		t.Errorf("ListForwards(main-1) = %v, want the one saved forward", h.LocalForwards)
	}
}

// forward --save on a managed host saves into the managed file before the run
// (the run itself is cut short by the missing ssh).
func TestForwardSave_ManagedHostSavesIntoTheManagedFile(t *testing.T) {
	mgNoSSHOnPath(t)
	e := newRtEnv(t)
	before := e.snap(t)
	d := rtDoc(t, e)
	canon, err := domain.ParseForwardSpec(domain.ForwardLocal, "8080:localhost:80")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddOptionValue("web-1", "LocalForward", canon); err != nil {
		t.Fatal(err)
	}
	runErr := e.a.RunForward("web-1", domain.ForwardLocal, []string{"8080:localhost:80"}, true)
	mgRequireErr(t, runErr)
	if !strings.Contains(runErr.Error(), "ssh not found") {
		t.Errorf("err = %v, want the ssh-not-found stop after the save", runErr)
	}
	if got, want := e.readManaged(t), string(d.Bytes()); got != want {
		t.Errorf("managed file:\n%s\nwant:\n%s", got, want)
	}
	rtOnlyManagedChanged(t, e, before)
}

// ---- R8: cert sign ----------------------------------------------------------------------

func rtKeygen(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
	}
}

func TestCertSign_WritesCertificateFileToTheManagedHost(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
	mgNeedSSH(t)
	mainBody := "Include @M@\n\nHost cert-main\n  HostName 10.0.0.91\n  User signer2\n  IdentityFile @D@/keys/k2\n\nHost *\n  User fallback\n"
	managedBody := mgManagedHeader + "\nHost cert-1\n  HostName 10.0.0.90\n  User signer\n  IdentityFile @D@/keys/k1\n"
	e := newMgEnv(t, mainBody, managedBody)
	keys := filepath.Join(e.dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(keys, "ca")
	rtKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", ca)
	rtKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(keys, "k1"))
	rtKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(keys, "k2"))
	e.backdate(t)
	orig := e.readManaged(t)

	// An unmanaged host: refused, and no certificate is left behind.
	before := e.snap(t)
	_, err := e.a.SignCert(SignOpts{HostName: "cert-main", CAKey: ca, Validity: "+1h"})
	mgRequireErr(t, err)
	var ume *UnmanagedHostError
	if !errors.As(err, &ume) || ume.Host != "cert-main" || !ume.CanImport {
		t.Fatalf("err = %v (%T), want an *UnmanagedHostError for cert-main with CanImport", err, err)
	}
	if mgExists(filepath.Join(keys, "k2-cert.pub")) {
		t.Error("a certificate was left behind for the unmanaged host (half-applied)")
	}
	mgRequireUnchanged(t, before, e.snap(t))

	// A managed host: the CertificateFile line lands in the managed file.
	before = e.snap(t)
	cert, err := e.a.SignCert(SignOpts{HostName: "cert-1", CAKey: ca, Validity: "+1h"})
	mgRequireNoErr(t, err)
	if want := filepath.Join(keys, "k1-cert.pub"); cert != want {
		t.Errorf("cert path = %q, want %q", cert, want)
	}
	want := []string{"added " + cert, "changed " + e.managed}
	sort.Strings(want)
	if d := mgDiff(before, e.snap(t), true); !reflect.DeepEqual(d, want) {
		t.Errorf("changed files = %v, want %v (main file untouched)", d, want)
	}
	if got := mgVal(mgSSHG(t, e.main, "cert-1"), "certificatefile"); got != cert {
		t.Errorf("ssh -G cert-1 certificatefile = %q, want %q", got, cert)
	}

	// Clearing it again goes through the managed file as well.
	mgRequireNoErr(t, e.a.ClearCertificateFile("cert-1"))
	if got := e.readManaged(t); got != orig {
		t.Errorf("managed file after ClearCertificateFile:\n%s\nwant the pre-sign bytes:\n%s", got, orig)
	}
}

// ---- R9: clearing options that feed %C ---------------------------------------------------

func TestClearingScalarOptions_WorksWhenNoTokenOptionIsInEffect(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	steps := []struct {
		key, line string // option key of EditHost and the line that must vanish
		ssh       func(out string) string
		want      string
	}{
		{"user", "  User carol\n", func(o string) string { return mgVal(o, "user") }, "fallback"},
		{"port", "  Port 2022\n", func(o string) string { return mgVal(o, "port") }, "2200"},
		{"proxyjump", "  ProxyJump jump.example.com\n", func(o string) string { return mgVal(o, "proxyjump") }, ""},
		{"hostkeyalias", "  HostKeyAlias clr-one\n", func(o string) string { return mgVal(o, "hostkeyalias") }, ""},
		{"hostname", "  HostName 10.0.0.20\n", func(o string) string { return mgVal(o, "hostname") }, "clr-1"},
	}
	for _, s := range steps {
		before := e.snap(t)
		prev := e.readManaged(t)
		if !strings.Contains(prev, "Host clr-1\n") || !strings.Contains(prev, s.line) {
			t.Fatalf("fixture lacks %q", s.line)
		}
		mgRequireNoErr(t, e.a.EditHost("clr-1", map[string]string{s.key: ""}))
		if got, want := e.readManaged(t), strings.Replace(prev, s.line, "", 1); got != want {
			t.Errorf("clearing %s:\n%s\nwant:\n%s", s.key, got, want)
		}
		rtOnlyManagedChanged(t, e, before)
		if got := s.ssh(mgSSHG(t, e.main, "clr-1")); got != s.want {
			t.Errorf("after clearing %s: ssh -G = %q, want %q", s.key, got, s.want)
		}
	}
}

func TestClearingScalarOptions_RolledBackWhenATokenOptionIsInEffect(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	const tokHost = "\nHost tok-1\n  HostName 10.0.0.30\n  User carol\n  Port 2022\n  ProxyJump jump.example.com\n"
	cases := []struct {
		name, mainBody, managedBody string
	}{
		{"ControlPath %C in the host block", rtMain, rtManaged + tokHost + "  ControlPath /tmp/sshm-test-%C\n"},
		{"ControlPath %C from Host * in the main file", strings.Replace(rtMain, "  Port 2200\n", "  Port 2200\n  ControlPath /tmp/sshm-test-%C\n", 1), rtManaged + tokHost},
	}
	for _, c := range cases {
		for _, key := range []string{"user", "hostname", "port", "proxyjump"} {
			t.Run(c.name+"/"+key, func(t *testing.T) {
				t.Parallel()
				e := newRtEnvWith(t, c.mainBody, c.managedBody)
				before := e.snap(t)
				resolved := mgSSHAll(t, e.main, []string{"tok-1", "web-1"})
				err := e.a.EditHost("tok-1", map[string]string{key: ""})
				mgRequireErr(t, err)
				for _, want := range []string{"token", "set a value instead or edit the file by hand"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q lacks %q", err, want)
					}
				}
				mgRequireRestored(t, before, e.snap(t), e.managed)
				mgRequireSameResolution(t, e.main, resolved)
			})
		}
	}
}

// ---- R10: groups ---------------------------------------------------------------------------

func TestGroups_DisableAndEnableInTheManagedFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	orig := e.readManaged(t)
	before := e.snap(t)

	mgRequireNoErr(t, e.a.DisableGroup("web"))
	got := e.readManaged(t)
	if !strings.Contains(got, domain.DisabledMarkerStart("web")) || !strings.Contains(got, domain.DisabledMarkerEnd("web")) {
		t.Errorf("managed file lacks the disabled-group markers:\n%s", got)
	}
	wantDiff := []string{"added " + mgSidecar(e.managed), "changed " + e.managed}
	if d := mgDiff(before, e.snap(t), true); !reflect.DeepEqual(d, wantDiff) {
		t.Errorf("changed files = %v, want %v (main file untouched)", d, wantDiff)
	}
	if side := mgSidecar(e.managed); !mgExists(side) || !mgHasLine(mgRead(t, side), "web") {
		t.Errorf("sidecar %s does not list the group", side)
	}
	if mgExists(mgSidecar(e.main)) {
		t.Error("the main file's sidecar was created in managed mode")
	}
	for _, h := range []string{"web-1", "web-2"} {
		if got := mgVal(mgSSHG(t, e.main, h), "hostname"); got != h {
			t.Errorf("disabled host %s still resolves: hostname = %q", h, got)
		}
	}
	states, err := e.a.ListGroupsState()
	mgRequireNoErr(t, err)
	found := false
	for _, s := range states {
		if s.Group == "web" {
			found = true
			if !reflect.DeepEqual(s.Disabled, []string{"web-1", "web-2"}) {
				t.Errorf("groups: web disabled = %v", s.Disabled)
			}
		}
	}
	if !found {
		t.Error("ListGroupsState lacks the web group")
	}
	if dis, err := e.a.IsGroupDisabled("web"); err != nil || !dis {
		t.Errorf("IsGroupDisabled(web) = %v, %v", dis, err)
	}

	mgRequireNoErr(t, e.a.EnableGroup("web"))
	if got := e.readManaged(t); got != orig {
		t.Errorf("disable + enable did not restore the managed file byte-for-byte:\n%s", got)
	}
	for _, p := range []string{e.main, e.extra()} {
		if e.snap(t)[p] != before[p] {
			t.Errorf("%s was touched", p)
		}
	}
	if side := mgSidecar(e.managed); mgExists(side) && mgHasLine(mgRead(t, side), "web") {
		t.Error("sidecar still lists the group after enable")
	}
	if got := mgVal(mgSSHG(t, e.main, "web-1"), "hostname"); got != "10.0.0.1" {
		t.Errorf("web-1 hostname = %q after enable", got)
	}
}

func TestGroups_DisableRefusedWhenAMemberIsOutsideTheManagedFile(t *testing.T) {
	t.Parallel()
	hostBlock := func(name string) string { return "Host " + name + "\n  HostName 10.0.0.1\n\n" }
	cases := []struct {
		name, mainBody, managedBody, extraBody string
		group                                  string
		listed                                 []string // expected UnmanagedHostError texts
		more                                   string   // expected "and N more", or ""
	}{
		{
			name:        "one member in the main file, one managed",
			mainBody:    "Include @M@\n\n" + hostBlock("deploy-2") + "Host *\n  User fallback\n",
			managedBody: mgManagedHeader + "\n" + hostBlock("deploy-1"),
			group:       "deploy",
			listed:      []string{"main:deploy-2"},
		},
		{
			name:        "whole group in the main file",
			mainBody:    "Include @M@\n\n" + hostBlock("solo-1") + hostBlock("solo-2") + "Host *\n  User fallback\n",
			managedBody: mgManagedHeader,
			group:       "solo",
			listed:      []string{"main:solo-1", "main:solo-2"},
		},
		{
			name:        "member in an included file",
			mainBody:    "Include @M@\nInclude @D@/extra.conf\n\nHost *\n  User fallback\n",
			managedBody: mgManagedHeader + "\n" + hostBlock("inc-2"),
			extraBody:   hostBlock("inc-1"),
			group:       "inc",
			listed:      []string{"extra:inc-1"},
		},
		{
			name: "five offenders: three listed, the rest counted",
			mainBody: "Include @M@\n\n" + hostBlock("many-1") + hostBlock("many-2") + hostBlock("many-3") +
				hostBlock("many-4") + hostBlock("many-5") + "Host *\n  User fallback\n",
			managedBody: mgManagedHeader + "\n" + hostBlock("many-0"),
			group:       "many",
			more:        "and 2 more",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, c.mainBody, c.managedBody)
			if c.extraBody != "" {
				mgWrite(t, e.extra(), c.extraBody, 0o600)
			}
			before := e.snap(t)
			err := e.a.DisableGroup(c.group)
			mgRequireErr(t, err)
			for _, l := range c.listed {
				kind, host, _ := strings.Cut(l, ":")
				want := rtUnmanaged(host, e.main, true)
				if kind == "extra" {
					want = rtUnmanaged(host, e.extra(), false)
				}
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q:\n%v", want, err)
				}
			}
			if c.more != "" {
				if n := strings.Count(err.Error(), "which sshm does not manage"); n != 3 {
					t.Errorf("error lists %d hosts, want 3:\n%v", n, err)
				}
				if !strings.Contains(err.Error(), c.more) {
					t.Errorf("error lacks %q:\n%v", c.more, err)
				}
			}
			mgRequireUnchanged(t, before, e.snap(t))
		})
	}
}

func TestGroups_EnableRefusedWhenADisabledBlockIsOutsideTheManagedFile(t *testing.T) {
	t.Parallel()
	const disabled = `# sshm disabled group=ops start
# Host %s
#   HostName 10.0.0.4%d
#   User opsuser
# sshm disabled group=ops end
`
	mainBody := "Include @M@\n\n" + fmt.Sprintf(disabled, "ops-1", 1) + "\nHost *\n  User fallback\n"
	cases := map[string]string{
		"disabled blocks only in the main file": mgManagedHeader + "\nHost web-1\n  HostName 10.0.0.1\n",
		"group split across both files":         mgManagedHeader + "\n" + fmt.Sprintf(disabled, "ops-2", 2),
	}
	for name, managed := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, mainBody, managed)
			before := e.snap(t)
			err := e.a.EnableGroup("ops")
			mgRequireErr(t, err)
			for _, want := range []string{"ops-1", "sshm import"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
			mgRequireUnchanged(t, before, e.snap(t))
		})
	}
}

// ---- R11: init ------------------------------------------------------------------------------

func TestInit_ManagedModeAppendsHostStarToTheMainFileOnlyWhenNoneExists(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	const mainNoStar = "Include @M@\n\n# hand-written\nHost main-1\n  HostName 10.0.0.9\n  User mainuser\n"
	e := newMgEnv(t, mainNoStar, rtManaged)
	origMain := e.readMain(t)
	before := e.snap(t)
	_, err := e.a.InitDefaults()
	mgRequireNoErr(t, err)
	gotMain := e.readMain(t)
	if !strings.HasPrefix(gotMain, origMain) {
		t.Fatalf("existing main bytes changed:\n%s", gotMain)
	}
	if d := mgDiff(before, e.snap(t), true); !reflect.DeepEqual(d, []string{"changed " + e.main}) {
		t.Errorf("changed files = %v, want only the main file (managed file byte- and mtime-identical)", d)
	}
	cfg, perr := config.Parse([]byte(gotMain))
	if perr != nil {
		t.Fatal(perr)
	}
	last := cfg.Hosts[len(cfg.Hosts)-1]
	if last.Name != "*" || last.StrictHostKeyChecking != "accept-new" {
		t.Errorf("last block = %q (StrictHostKeyChecking %q), want Host * with accept-new at the END of the main file", last.Name, last.StrictHostKeyChecking)
	}
	// ssh parses the result and the hand-written host is unchanged.
	out := mgSSHG(t, e.main, "main-1")
	if mgVal(out, "hostname") != "10.0.0.9" || mgVal(out, "user") != "mainuser" {
		t.Errorf("main-1 resolves differently after init:\n%s", out)
	}

	// Same algorithm filtering as in legacy mode: the option lines of Host * match.
	legacy := newMgEnv(t, strings.TrimPrefix(mainNoStar, "Include @M@\n\n"), mgAbsent)
	_, lerr := legacy.a.InitDefaults()
	mgRequireNoErr(t, lerr)
	starOptions := func(text string) []string {
		var out []string
		in := false
		for _, l := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(trimmed, "Host "):
				in = trimmed == "Host *"
			case in && trimmed != "" && !strings.HasPrefix(trimmed, "#"):
				out = append(out, trimmed)
			}
		}
		sort.Strings(out)
		return out
	}
	if got, want := starOptions(gotMain), starOptions(legacy.readMain(t)); len(want) == 0 || !reflect.DeepEqual(got, want) {
		t.Errorf("Host * options differ from legacy init:\nmanaged: %q\nlegacy:  %q", got, want)
	}
}

func TestInit_ManagedModeLeavesAnExistingHostStarAloneAndSaysWhere(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, mainBody, managedBody, extraBody string
		file                                   func(e *mgEnv) string
	}{
		{"in the main file", rtMain, rtManaged, rtExtra, func(e *mgEnv) string { return e.main }},
		{"in the managed file", "Include @M@\n\nHost main-1\n  HostName 10.0.0.9\n", rtManaged + "\nHost *\n  ServerAliveInterval 20\n", rtExtra, func(e *mgEnv) string { return e.managed }},
		{"in an included file", "Include @M@\nInclude @D@/extra.conf\n\nHost main-1\n  HostName 10.0.0.9\n", rtManaged, rtExtra + "\nHost *\n  Compression no\n", func(e *mgEnv) string { return e.extra() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, c.mainBody, c.managedBody)
			mgWrite(t, e.extra(), c.extraBody, 0o600)
			file := c.file(e)
			star := 0
			for i, l := range mgLines(mgRead(t, file)) {
				if l == "Host *" && star == 0 {
					star = i + 1
				}
			}
			before := e.snap(t)
			note, err := e.a.InitDefaults()
			text := note
			if err != nil {
				text += " " + err.Error()
			}
			if errors.Is(err, ErrNotImplemented) {
				t.Fatalf("got the skeleton's ErrNotImplemented")
			}
			if want := fmt.Sprintf("%s:%d", file, star); !strings.Contains(text, want) {
				t.Errorf("message %q does not name %s", text, want)
			}
			if !strings.Contains(text, "does not rewrite") {
				t.Errorf("message %q does not say that sshm does not rewrite it", text)
			}
			mgRequireUnchanged(t, before, e.snap(t))
		})
	}
}

// ---- R12: read commands (characterization) -----------------------------------------------------

func rtReadView(t *testing.T, e *mgEnv) string {
	t.Helper()
	var b strings.Builder
	dump := func(hs []domain.Host) {
		for _, h := range hs {
			h.SourceFile = ""
			fmt.Fprintf(&b, "%+v\n", h)
		}
	}
	all, err := e.a.ListHosts("", true)
	mgRequireNoErr(t, err)
	dump(all)
	web, err := e.a.ListHosts("web", false)
	mgRequireNoErr(t, err)
	dump(web)
	groups, err := e.a.ListGroups()
	mgRequireNoErr(t, err)
	var gnames []string
	for g, hs := range groups {
		var names []string
		for _, h := range hs {
			names = append(names, h.Name)
		}
		gnames = append(gnames, g+"="+strings.Join(names, ","))
	}
	sort.Strings(gnames)
	fmt.Fprintf(&b, "groups: %v\n", gnames)
	states, err := e.a.ListGroupsState()
	mgRequireNoErr(t, err)
	fmt.Fprintf(&b, "states: %+v\n", states)
	d, err := e.a.Dump("web-1")
	mgRequireNoErr(t, err)
	d.SourceFile = ""
	fmt.Fprintf(&b, "dump: %+v\n", d)
	issues, err := e.a.Validate()
	mgRequireNoErr(t, err)
	fmt.Fprintf(&b, "validate: %+v\n", issues)
	comp, err := e.a.HostNamesForCompletion("w")
	mgRequireNoErr(t, err)
	fmt.Fprintf(&b, "completion: %v\n", comp)
	return strings.NewReplacer("<D>/other.conf", "<D>/config.d/sshm.conf").Replace(strings.ReplaceAll(b.String(), e.dir, "<D>"))
}

// The same hosts, once reached through an Include of the managed path
// (managed mode) and once through an Include of another file (legacy mode):
// the read commands print the same.
func TestReadCommands_BehaveTheSameInBothModes(t *testing.T) {
	t.Parallel()
	const body = mgManagedHeader + `
Host web-1
  HostName 10.0.0.1
  User alice

Host web-2
  HostName 10.0.0.3

Host main-1
  HostName 10.0.0.19

# sshm disabled group=ops start
# Host ops-1
#   HostName 10.0.0.41
# sshm disabled group=ops end
`
	const mainTail = "\n# hand-written\nHost main-1\n  HostName 10.0.0.9\n\nHost *\n  User fallback\n"
	managedMode := newMgEnv(t, "Include @M@\n"+mainTail, body)
	legacyMode := newMgEnv(t, "Include @D@/other.conf\n"+mainTail, mgAbsent)
	mgWrite(t, filepath.Join(legacyMode.dir, "other.conf"), body, 0o600)

	got, want := rtReadView(t, managedMode), rtReadView(t, legacyMode)
	if got != want {
		t.Errorf("read commands differ between modes:\nmanaged mode:\n%s\nlegacy mode:\n%s", got, want)
	}
}

// ---- R13: backups, mode, rollback ---------------------------------------------------------------

func TestManagedWrites_BackupsRetentionModeAndRollback(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	if err := os.Chmod(e.managed, 0o644); err != nil { // acceptable for ssh, but sshm must tighten it
		t.Fatal(err)
	}
	orig := e.readManaged(t)

	mgRequireNoErr(t, e.a.EditHost("web-1", map[string]string{"user": "u1"}))
	if m := mgMode(t, e.managed); m != 0o600 {
		t.Errorf("managed mode after a write = %o, want 0600", m)
	}
	baks := mgBackupWith(t, e.dir, orig)
	if len(baks) != 1 {
		t.Fatalf("backups holding the previous managed file: %v, want exactly 1", baks)
	}
	if !strings.HasPrefix(filepath.Base(baks[0]), "sshm.conf.") {
		t.Errorf("backup name = %s, want sshm.conf.<stamp>", filepath.Base(baks[0]))
	}
	if m := mgMode(t, baks[0]); m != 0o600 {
		t.Errorf("backup mode = %o, want 0600", m)
	}
	if m := mgMode(t, e.backupDir()); m != 0o700 {
		t.Errorf("sshm-backups mode = %o, want 0700", m)
	}

	// Newest 20 kept.
	var prev string
	for i := 2; i <= 23; i++ {
		prev = e.readManaged(t)
		mgRequireNoErr(t, e.a.EditHost("web-1", map[string]string{"user": fmt.Sprintf("u%d", i)}))
	}
	var managedBaks []string
	for p := range mgBackupFiles(t, e.dir) {
		if strings.HasPrefix(filepath.Base(p), "sshm.conf.") {
			managedBaks = append(managedBaks, p)
		}
	}
	if len(managedBaks) != 20 {
		t.Errorf("managed-file backups = %d, want the newest 20 kept", len(managedBaks))
	}
	if len(mgBackupWith(t, e.dir, orig)) != 0 {
		t.Error("the oldest backup survived the retention limit")
	}
	if len(mgBackupWith(t, e.dir, prev)) != 1 {
		t.Error("the newest backup (content before the last edit) is missing")
	}

	// An edit ssh rejects is rolled back byte-for-byte.
	pre := e.readManaged(t)
	mainBefore := e.snap(t)[e.main]
	for _, ch := range []map[string]string{{"loglevel": "bogus"}, {"port": "abc"}} {
		err := e.a.EditHost("web-1", ch)
		mgRequireErr(t, err)
		if got := e.readManaged(t); got != pre {
			t.Errorf("%v: managed file not restored byte-for-byte:\n%s", ch, got)
		}
		if m := mgMode(t, e.managed); m != 0o600 {
			t.Errorf("%v: mode after rollback = %o", ch, m)
		}
		if e.snap(t)[e.main] != mainBefore {
			t.Errorf("%v: main file touched", ch)
		}
		if got := mgVal(mgSSHG(t, e.main, "web-1"), "user"); got != "u23" {
			t.Errorf("%v: ssh config broken after rollback, user = %q", ch, got)
		}
	}
}
