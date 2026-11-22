package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// noExecPath empties PATH so a gate regression can never exec a real
// ssh/rsync/ssh-keygen from a test: LookPath fails instead.
func noExecPath(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

func wantDisabledErr(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected disabled-group error, got nil", what)
		return
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("%s: error should mention disabled group, got: %v", what, err)
	}
}

// TestSignCertDisabledHost: signing by host name must be refused for a host
// in a disabled group.
func TestSignCertDisabledHost(t *testing.T) {
	noExecPath(t)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	key := filepath.Join(dir, "id_test")
	for _, p := range []string{ca, key + ".pub"} {
		if err := os.WriteFile(p, []byte("placeholder\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := newSetUpTestApp(t, "Host deploy-acq\n  HostName 192.0.2.10\n  User deploy\n  IdentityFile "+key+"\n")
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}

	_, err := a.SignCert(SignOpts{HostName: "deploy-acq", CAKey: ca})
	wantDisabledErr(t, "SignCert", err)
}

// TestGateCoversHostAddedToDisabledGroup: a host that appears in a group
// after it was disabled (not commented out) is still gated via the state file.
func TestGateCoversHostAddedToDisabledGroup(t *testing.T) {
	noExecPath(t)
	a := newSetUpTestApp(t, groupFixture)
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddHost(domain.Host{Name: "deploy-new", HostName: "192.0.2.50", User: "deploy"}); err != nil {
		t.Fatal(err)
	}

	l, err := a.loadAll()
	if err != nil {
		t.Fatal(err)
	}
	idx := findHostIndex(l.Hosts, "deploy-new")
	if idx == -1 || l.Hosts[idx].Disabled {
		t.Fatalf("test setup: deploy-new must be a present, not-commented-out host (idx=%d)", idx)
	}

	wantDisabledErr(t, "Connect", a.Connect("deploy-new", nil))
	wantDisabledErr(t, "Copy", a.Copy("/nonexistent/file", "deploy-new:/tmp/file", ""))
	wantDisabledErr(t, "RunForward", a.RunForward("deploy-new", domain.ForwardLocal, []string{"8080:localhost:80"}, false))
	wantDisabledErr(t, "AddForward", a.AddForward("deploy-new", domain.ForwardLocal, []string{"8080:localhost:80"}))
	wantDisabledErr(t, "ClearForwards", a.ClearForwards("deploy-new"))

	hosts, err := a.ListHosts("", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.Name == "deploy-new" {
			t.Error("ListHosts hides disabled-group hosts by default, but returned deploy-new")
		}
	}
	all, err := a.ListHosts("", true)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, h := range all {
		found = found || h.Name == "deploy-new"
	}
	if !found {
		t.Error("ListHosts(includeDisabled) should return deploy-new")
	}

	names, err := a.HostNamesForCompletion("")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "deploy-new" {
			t.Error("completion offered deploy-new from a disabled group")
		}
	}

	// Enabling the group opens the gate again.
	if err := a.EnableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	l, err = a.loadAll()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ensureHostNotDisabled(l.Hosts, "deploy-new"); err != nil {
		t.Errorf("deploy-new still gated after enable: %v", err)
	}
}

// TestCopyFailsClosedOnUnloadableConfig: if the config cannot be loaded the
// gate must not be skipped.
func TestCopyFailsClosedOnUnloadableConfig(t *testing.T) {
	noExecPath(t)
	// Unterminated disabled block -> Parse error.
	broken := domain.DisabledMarkerStart("deploy") + "\n# Host deploy-acq\n"
	for _, dst := range []string{"deploy-acq:/tmp/file", "root@192.0.2.10:/tmp/file"} {
		a := newTestApp(t, broken)
		err := a.Copy("/nonexistent/file", dst, "")
		if err == nil {
			t.Fatalf("Copy to %q with unloadable config should fail", dst)
		}
		if !strings.Contains(err.Error(), "parse config") {
			t.Errorf("Copy to %q: want the config load error, got: %v", dst, err)
		}
	}
}
