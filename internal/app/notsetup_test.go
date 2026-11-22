package app

// P7 clauses G1-G4, G6, G7 at the App level (PLAN-p7.md section 4 and 7).
// The CLI side is in internal/cli/notsetup_test.go.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// nsCall is one App method call that the gate must refuse. emptyPath: the call
// ends in syscall.Exec when it gets that far, so PATH is emptied and it stops
// at "ssh not found" instead.
type nsCall struct {
	name      string
	emptyPath bool
	call      func(a *App) error
}

func nsGatedCalls() []nsCall {
	chg := map[string]string{"user": "zed"}
	fwd := func(host string) func(a *App) error {
		return func(a *App) error {
			return a.AddForward(host, domain.ForwardLocal, []string{"8080:localhost:80"})
		}
	}
	return []nsCall{
		{name: "AddHost", call: func(a *App) error { return a.AddHost(domain.Host{Name: "new-1", HostName: "10.9.9.9"}) }},
		{name: "AddHost/G3 already exists", call: func(a *App) error { return a.AddHost(domain.Host{Name: "web-1", HostName: "10.9.9.9"}) }},
		{name: "AddHost/G3 exists in included file", call: func(a *App) error { return a.AddHost(domain.Host{Name: "inc-1", HostName: "10.9.9.9"}) }},

		{name: "EditHost", call: func(a *App) error { return a.EditHost("web-1", chg) }},
		{name: "EditHost/G3 not found", call: func(a *App) error { return a.EditHost("ghost", chg) }},
		{name: "EditHost/G3 included host", call: func(a *App) error { return a.EditHost("inc-1", chg) }},
		{name: "EditHost/G3 one pattern of a multi-pattern line", call: func(a *App) error { return a.EditHost("p-1", chg) }},
		{name: "EditHost/G3 whole multi-pattern line text", call: func(a *App) error { return a.EditHost("p-1 p-2", chg) }},

		{name: "DeleteHost", call: func(a *App) error { return a.DeleteHost("db-1") }},
		{name: "DeleteHost/G3 not found", call: func(a *App) error { return a.DeleteHost("ghost") }},
		{name: "DeleteHost/G3 included host", call: func(a *App) error { return a.DeleteHost("inc-1") }},
		{name: "DeleteHost/G3 one pattern of a multi-pattern line", call: func(a *App) error { return a.DeleteHost("p-2") }},

		{name: "DuplicateHost", call: func(a *App) error { return a.DuplicateHost("web-1", "web-9") }},
		{name: "DuplicateHost/G3 source not found", call: func(a *App) error { return a.DuplicateHost("ghost", "web-9") }},
		{name: "DuplicateHost/G3 target exists", call: func(a *App) error { return a.DuplicateHost("web-1", "db-1") }},
		{name: "DuplicateHost/G3 target exists in included file", call: func(a *App) error { return a.DuplicateHost("web-1", "inc-1") }},
		{name: "DuplicateHost/G3 included source", call: func(a *App) error { return a.DuplicateHost("inc-1", "inc-9") }},
		{name: "DuplicateHost/G3 multi-pattern source", call: func(a *App) error { return a.DuplicateHost("p-1", "p-9") }},

		{name: "AddForward", call: fwd("web-1")},
		{name: "AddForward/G3 not found", call: fwd("ghost")},
		{name: "AddForward/G3 included host", call: fwd("inc-1")},
		{name: "AddForward/G3 multi-pattern", call: fwd("p-1")},
		{name: "ClearForwards", call: func(a *App) error { return a.ClearForwards("web-1") }},
		{name: "ClearForwards/G3 not found", call: func(a *App) error { return a.ClearForwards("ghost") }},
		{name: "ClearForwards/G3 included host", call: func(a *App) error { return a.ClearForwards("inc-1") }},
		{name: "RunForward with save", emptyPath: true, call: func(a *App) error {
			return a.RunForward("web-1", domain.ForwardLocal, []string{"8080:localhost:80"}, true)
		}},
		{name: "RunForward with save/G3 not found", emptyPath: true, call: func(a *App) error {
			return a.RunForward("ghost", domain.ForwardLocal, []string{"8080:localhost:80"}, true)
		}},

		{name: "ClearCertificateFile", call: func(a *App) error { return a.ClearCertificateFile("web-1") }},
		{name: "ClearCertificateFile/clar 5 unknown host is no silent nil", call: func(a *App) error { return a.ClearCertificateFile("ghost") }},
		{name: "ClearCertificateFile/G3 included host", call: func(a *App) error { return a.ClearCertificateFile("inc-1") }},

		{name: "DisableGroup", call: func(a *App) error { return a.DisableGroup("web") }},
		{name: "DisableGroup/clar 2 invalid group name", call: func(a *App) error { return a.DisableGroup("bad name") }},
		{name: "DisableGroup/G3 unknown group", call: func(a *App) error { return a.DisableGroup("nosuchgroup") }},
		{name: "EnableGroup", call: func(a *App) error { return a.EnableGroup("web") }},
		{name: "EnableGroup/clar 2 invalid group name", call: func(a *App) error { return a.EnableGroup("bad name") }},
		{name: "EnableGroup/G3 unknown group", call: func(a *App) error { return a.EnableGroup("nosuchgroup") }},

		{name: "InitDefaults/clar 6", call: func(a *App) error { _, err := a.InitDefaults(); return err }},
		{name: "InitDefaultsReport/clar 6", call: func(a *App) error { _, _, err := a.InitDefaultsReport(); return err }},

		{name: "CheckEdit", call: func(a *App) error { _, err := a.CheckEdit("web-1", chg); return err }},
		{name: "CheckEdit/G3 not found", call: func(a *App) error { _, err := a.CheckEdit("ghost", chg); return err }},
		{name: "CheckEdit/G3 included host", call: func(a *App) error { _, err := a.CheckEdit("inc-1", chg); return err }},
		{name: "CheckEdit/G3 multi-pattern", call: func(a *App) error { _, err := a.CheckEdit("p-1", chg); return err }},
	}
}

// G1, G2, G3: every gated method returns ErrNotSetUp on a main file without an
// Include of the managed file, whatever else is wrong with its arguments, and
// changes nothing under the ssh dir.
func TestNotSetUp_GateRefusesEveryWrite(t *testing.T) {
	for _, c := range nsGatedCalls() {
		t.Run(c.name, func(t *testing.T) {
			e := nsNotSetUp(t)
			if c.emptyPath {
				nsEmptyPath(t)
			}
			before := nsSnap(t, e.dir)
			err := c.call(e.a)
			nsRequireGate(t, err)
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// G1: the gate asks for an Include, not for a managed file: a managed file that
// exists but is not included, and an Include that sits under a Host line (ssh
// applies it only for that host), both count as not set up.
func TestNotSetUp_GateWhenManagedFileExistsButIsNotIncluded(t *testing.T) {
	cases := map[string]string{
		"managed file exists, main has no Include": nsNotSetUpMain,
		"conditional Include below a Host line":    "Host cond\n  Include @M@\n\n" + nsHostBlocks + nsTail,
	}
	for name, mainBody := range cases {
		t.Run(name, func(t *testing.T) {
			e := nsNew(t, mainBody, nsSetUpManaged)
			before := nsSnap(t, e.dir)
			nsRequireGate(t, e.a.AddHost(domain.Host{Name: "new-1", HostName: "10.9.9.9"}))
			nsRequireGate(t, e.a.EditHost("web-1", map[string]string{"user": "zed"}))
			nsRequireGate(t, e.a.DeleteHost("db-1"))
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// Control for the gate tests: on a set-up config none of the calls is refused by
// the gate (a gate that always refuses would pass every test above). Green now.
func TestSetUp_GateDoesNotRefuse(t *testing.T) {
	for _, c := range nsGatedCalls() {
		t.Run(c.name, func(t *testing.T) {
			e := nsSetUp(t)
			if c.emptyPath {
				nsEmptyPath(t)
			}
			if err := c.call(e.a); errors.Is(err, ErrNotSetUp) {
				t.Fatalf("set-up config refused with the gate error: %v", err)
			}
		})
	}
	t.Run("a valid write still works", func(t *testing.T) {
		e := nsSetUp(t)
		if err := e.a.EditHost("web-1", map[string]string{"user": "zed"}); err != nil {
			t.Fatalf("EditHost: %v", err)
		}
		if got := e.readManaged(t); !strings.Contains(got, "User zed") {
			t.Fatalf("managed file lacks the edit:\n%s", got)
		}
	})
}

// G4: the main file does not exist: every gated method returns ErrNotSetUp, not
// the read error, and creates nothing.
func TestNotSetUp_MissingMainFileIsNotSetUp(t *testing.T) {
	for _, c := range nsGatedCalls() {
		t.Run(c.name, func(t *testing.T) {
			e := nsNew(t, mgAbsent, mgAbsent)
			if c.emptyPath {
				nsEmptyPath(t)
			}
			before := nsSnap(t, e.dir)
			err := c.call(e.a)
			nsRequireGate(t, err)
			if strings.Contains(err.Error(), "read config") || strings.Contains(err.Error(), "no such file") {
				t.Errorf("G4: the error mentions the missing file: %v", err)
			}
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// G4: any other read or parse error keeps today's message (no ErrNotSetUp).
// Characterization, green now.
func TestNotSetUp_OtherReadErrorsKeepTheirMessage(t *testing.T) {
	e := nsNew(t, mgAbsent, mgAbsent)
	if err := os.Mkdir(e.main, 0o700); err != nil { // the main "file" is a directory
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"AddHost":      func() error { return e.a.AddHost(domain.Host{Name: "new-1"}) },
		"EditHost":     func() error { return e.a.EditHost("web-1", map[string]string{"user": "x"}) },
		"DeleteHost":   func() error { return e.a.DeleteHost("web-1") },
		"ClearForward": func() error { return e.a.ClearForwards("web-1") },
	} {
		err := call()
		if err == nil {
			t.Errorf("%s: no error for a main file that cannot be read", name)
			continue
		}
		if errors.Is(err, ErrNotSetUp) || errors.Is(err, ErrNotImplemented) {
			t.Errorf("%s: got %v, want the read error unchanged", name, err)
		}
		if !strings.Contains(err.Error(), e.main) {
			t.Errorf("%s: error %q does not name the main file %s", name, err, e.main)
		}
	}
}

// G1 + clarification 2/3: SignCert with a host is gated before the CA key and
// public key lookup and before ssh-keygen runs; nothing is created, no
// certificate either.
func TestNotSetUp_SignCertWithHostIsGated(t *testing.T) {
	cases := []struct {
		name string
		opts func(e *mgEnv) SignOpts
	}{
		{"everything valid", func(e *mgEnv) SignOpts {
			return SignOpts{HostName: "sign-1", CAKey: filepath.Join(e.dir, "keys", "ca")}
		}},
		{"clar 2: CA key missing", func(e *mgEnv) SignOpts {
			return SignOpts{HostName: "sign-1", CAKey: filepath.Join(e.dir, "keys", "no-such-ca")}
		}},
		{"clar 2: no CA key given and none stored", func(e *mgEnv) SignOpts { return SignOpts{HostName: "sign-1"} }},
		{"clar 2: public key missing", func(e *mgEnv) SignOpts {
			return SignOpts{HostName: "sign-1", CAKey: filepath.Join(e.dir, "keys", "ca"), PubKeyPath: filepath.Join(e.dir, "keys", "none.pub")}
		}},
		{"G3: host not found", func(e *mgEnv) SignOpts {
			return SignOpts{HostName: "ghost", CAKey: filepath.Join(e.dir, "keys", "ca")}
		}},
		{"G3: multi-pattern host", func(e *mgEnv) SignOpts {
			return SignOpts{HostName: "p-1", CAKey: filepath.Join(e.dir, "keys", "ca")}
		}},
		{"G3: host in an included file", func(e *mgEnv) SignOpts {
			return SignOpts{HostName: "inc-1", CAKey: filepath.Join(e.dir, "keys", "ca")}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := nsNotSetUp(t)
			marker := nsFakeKeygen(t)
			before := nsSnap(t, e.dir)
			_, err := e.a.SignCert(c.opts(e))
			nsRequireGate(t, err)
			if _, serr := os.Stat(marker); serr == nil {
				t.Errorf("ssh-keygen was run (marker %s exists)", marker)
			}
			if mgExists(filepath.Join(e.dir, "keys", "sign1-cert.pub")) {
				t.Errorf("a certificate was created")
			}
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// Clarification 3: SignCert WITHOUT a host writes nothing to the config and has
// no gate. Characterization, green now.
func TestNotSetUp_SignCertWithoutHostHasNoGate(t *testing.T) {
	e := nsNotSetUp(t)
	marker := nsFakeKeygen(t)
	cfgBefore := e.readMain(t)
	pub := filepath.Join(e.dir, "keys", "sign1.pub")
	got, err := e.a.SignCert(SignOpts{PubKeyPath: pub, CAKey: filepath.Join(e.dir, "keys", "ca"), Principals: "carol"})
	if err != nil {
		t.Fatalf("SignCert without host on a config that is not set up: %v", err)
	}
	if want := filepath.Join(e.dir, "keys", "sign1-cert.pub"); got != want {
		t.Errorf("certificate path = %q, want %q", got, want)
	}
	if _, serr := os.Stat(marker); serr != nil {
		t.Errorf("ssh-keygen did not run: %v", serr)
	}
	if e.readMain(t) != cfgBefore {
		t.Error("the config changed")
	}
	if mgExists(e.managed) {
		t.Error("a managed file appeared")
	}
}

// Control: with a set-up config SignCert with a host works and records the
// CertificateFile in the managed file. Green now.
func TestSetUp_SignCertWithHostRecordsCertificate(t *testing.T) {
	e := nsSetUp(t)
	nsFakeKeygen(t)
	got, err := e.a.SignCert(SignOpts{HostName: "sign-1", CAKey: filepath.Join(e.dir, "keys", "ca")})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	if !strings.Contains(e.readManaged(t), "CertificateFile "+got) {
		t.Errorf("managed file lacks CertificateFile %s:\n%s", got, e.readManaged(t))
	}
}

// Clarification 4 / G1 / G2: RevokeCert gates when a host references the
// certificate; nothing is deleted. "cert file not found" still comes first.
func TestNotSetUp_RevokeCertReferencedByHostIsGated(t *testing.T) {
	e := nsNotSetUp(t)
	cert := filepath.Join(e.dir, "keys", "web1-cert.pub") // web-1 has CertificateFile <this>
	before := nsSnap(t, e.dir)

	err := e.a.RevokeCert(cert)
	if err == nil {
		t.Fatal("RevokeCert returned no error")
	}
	if !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("got %q, want an error wrapping ErrNotSetUp", err)
	}
	if !strings.Contains(err.Error(), nsGateText) {
		t.Fatalf("error %q does not contain %q", err, nsGateText)
	}
	if !mgExists(cert) {
		t.Error("the certificate file was deleted")
	}
	nsRequireSame(t, before, nsSnap(t, e.dir))
}

func TestNotSetUp_RevokeCertFileNotFoundComesFirst(t *testing.T) {
	e := nsNotSetUp(t)
	before := nsSnap(t, e.dir)
	err := e.a.RevokeCert(filepath.Join(e.dir, "keys", "no-such-cert.pub"))
	if err == nil || !strings.Contains(err.Error(), "cert file not found") {
		t.Fatalf("got %v, want 'cert file not found'", err)
	}
	if errors.Is(err, ErrNotSetUp) {
		t.Errorf("the gate must not fire before the cert file is found: %v", err)
	}
	nsRequireSame(t, before, nsSnap(t, e.dir))
}

// G6: cert revoke without a referencing host is not gated: the file is deleted,
// the config is not touched. Characterization, green now.
func TestNotSetUp_RevokeCertWithoutReferencingHostWorks(t *testing.T) {
	e := nsNotSetUp(t)
	cert := filepath.Join(e.dir, "keys", "orphan-cert.pub")
	cfg := e.readMain(t)
	if err := e.a.RevokeCert(cert); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	if mgExists(cert) {
		t.Error("the certificate file was not deleted")
	}
	if e.readMain(t) != cfg {
		t.Error("the config changed")
	}
}

// G6: read-only methods behave as before on a config that is not set up and
// change nothing. Characterization, green now.
func TestNotSetUp_ReadOnlyMethodsUnchanged(t *testing.T) {
	e := nsNotSetUp(t)
	before := nsSnap(t, e.dir)

	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Managed || snap.ManagedProblem != "" || snap.ManagedPath != e.managed {
		t.Errorf("Snapshot Managed=%v ManagedProblem=%q ManagedPath=%q", snap.Managed, snap.ManagedProblem, snap.ManagedPath)
	}
	names := map[string]bool{}
	for _, h := range snap.Hosts {
		names[h.Name] = true
	}
	for _, want := range []string{"web-1", "db-1", "inc-1", "sign-1", "*"} {
		if !names[want] {
			t.Errorf("Snapshot lacks host %q (have %v)", want, names)
		}
	}
	if _, err := e.a.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	h, err := e.a.Dump("web-1")
	if err != nil || h.HostName != "10.0.0.1" {
		t.Errorf("Dump(web-1) = %q, %v", h.HostName, err)
	}
	if gs, err := e.a.ListGroupsState(); err != nil || len(gs) == 0 {
		t.Errorf("ListGroupsState = %v, %v", gs, err)
	}
	if h, err := e.a.ListForwards("web-1"); err != nil || h.Name != "web-1" {
		t.Errorf("ListForwards = %q, %v", h.Name, err)
	}
	if err := e.a.CheckHostName("brand-new"); err != nil {
		t.Errorf("CheckHostName(new): %v", err)
	}
	if err := e.a.CheckHostName("web-1"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("CheckHostName(web-1) = %v, want 'already exists'", err)
	}
	if issues, err := e.a.CheckNewHost(domain.Host{Name: "brand-new"}); err != nil {
		t.Errorf("CheckNewHost: %v (%v)", err, issues)
	}
	nsRequireSame(t, before, nsSnap(t, e.dir))

	nsEmptyPath(t)
	for name, err := range map[string]error{
		"Connect": e.a.Connect("web-1", nil),
		"Copy":    e.a.Copy("web-1:/tmp/x", filepath.Join(e.dir, "x"), "-a"),
	} {
		if err == nil || errors.Is(err, ErrNotSetUp) || !strings.Contains(err.Error(), "not found in PATH") {
			t.Errorf("%s = %v, want the 'not found in PATH' stop and no gate", name, err)
		}
	}
	nsRequireSame(t, before, nsSnap(t, e.dir))
}

// G6 + G4: read-only methods on a missing main file keep the read error, they
// are not gated. Characterization, green now.
func TestNotSetUp_ReadOnlyMethodsOnMissingMainKeepReadError(t *testing.T) {
	e := nsNew(t, mgAbsent, mgAbsent)
	wantErr := "open " + e.main + ": no such file or directory"
	calls := map[string]func() error{
		"Snapshot":        func() error { _, err := e.a.Snapshot(); return err },
		"Validate":        func() error { _, err := e.a.Validate(); return err },
		"Dump":            func() error { _, err := e.a.Dump("web-1"); return err },
		"ListGroupsState": func() error { _, err := e.a.ListGroupsState(); return err },
		"ListForwards":    func() error { _, err := e.a.ListForwards("web-1"); return err },
		"CheckHostName":   func() error { return e.a.CheckHostName("x-1") }, // item 7
		"CheckNewHost":    func() error { _, err := e.a.CheckNewHost(domain.Host{Name: "x-1"}); return err },
		"Connect":         func() error { return e.a.Connect("web-1", nil) },
	}
	for name, call := range calls {
		err := call()
		if name == "CheckNewHost" {
			// CheckNewHost reports the name problem as an issue, not as an error.
			continue
		}
		if err == nil || errors.Is(err, ErrNotSetUp) || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s = %v, want the read error containing %q", name, err, wantErr)
		}
	}
	issues, err := e.a.CheckNewHost(domain.Host{Name: "x-1"})
	if err != nil {
		t.Errorf("CheckNewHost returned an error: %v", err)
	}
	found := false
	for _, i := range issues {
		if i.Rule == "host-name" && strings.Contains(i.Message, wantErr) {
			found = true
		}
	}
	if !found {
		t.Errorf("CheckNewHost issues %v lack a host-name issue with the read error %q", issues, wantErr)
	}
}

// G7: the TUI decides on Snapshot.Managed; a config that is not set up keeps
// Managed false, no ManagedProblem and the hosts visible; CheckEdit returns the
// gate error so no editor form can open. (The toast itself is pinned by the
// existing TUI tests TestEditingDisabledByDefault and
// TestIncludedHostEditKeysStayDisabled, which must stay green.)
func TestNotSetUp_SnapshotAndCheckEditForTheTUI(t *testing.T) {
	e := nsNotSetUp(t)
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Managed || snap.ManagedProblem != "" {
		t.Errorf("Managed=%v ManagedProblem=%q, want false and empty", snap.Managed, snap.ManagedProblem)
	}
	if len(snap.Hosts) == 0 {
		t.Fatal("Snapshot has no hosts")
	}
	_, err = e.a.CheckEdit("web-1", map[string]string{"user": "x"})
	nsRequireGate(t, err)
}
