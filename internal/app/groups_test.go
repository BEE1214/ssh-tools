package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// newTestApp writes a config fixture to a temp dir and returns an App
// rooted at it. The config is NOT set up (no Include of a managed file): use
// it for read-only tests and for the gate; write tests use newSetUpTestApp.
func newTestApp(t *testing.T, config string) *App {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewAppWithPath(path)
}

// newSetUpTestApp is newTestApp for a set-up config: the main file holds only
// the Include line, hosts is the content of the managed file after its header.
func newSetUpTestApp(t *testing.T, hosts string) *App {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "config")
	managed := filepath.Join(dir, "config.d", "sshm.conf")
	if err := os.Mkdir(filepath.Dir(managed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte(mgManagedHeader+"\n"+hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte("Include "+managed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewAppWithPath(main)
}

const groupFixture = `Host web-1
  HostName 10.0.0.1
  User admin

Host deploy-acq
  HostName 192.168.1.10
  User deploy

Host deploy-eu
  HostName 192.168.1.11
  User deploy

Host misc
  HostName 10.0.0.9
`

// configAfter returns the file the writes of a go to: the managed file of a
// set-up config, else the main file.
func configAfter(t *testing.T, a *App) string {
	t.Helper()
	path := a.ConfigPath()
	if active, err := a.ManagedActive(); err == nil && active {
		path = a.ManagedPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestDisableEnableCycle covers the full disable → config check → enable
// cycle against a temp config.
func TestDisableEnableCycle(t *testing.T) {
	a := newSetUpTestApp(t, groupFixture)

	// Disable the deploy group.
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatalf("DisableGroup: %v", err)
	}

	after := configAfter(t, a)

	// Deploy hosts must be between markers, disabled.
	if !strings.Contains(after, domain.DisabledMarkerStart("deploy")) {
		t.Errorf("start marker missing:\n%s", after)
	}
	if !strings.Contains(after, domain.DisabledMarkerEnd("deploy")) {
		t.Errorf("end marker missing:\n%s", after)
	}
	if !strings.Contains(after, "Host deploy-acq") || !strings.Contains(after, "Host deploy-eu") {
		t.Errorf("deploy blocks missing:\n%s", after)
	}
	// Non-deploy hosts must remain outside the disabled section.
	startIdx := strings.Index(after, domain.DisabledMarkerStart("deploy"))
	endIdx := strings.Index(after, domain.DisabledMarkerEnd("deploy"))
	if startIdx == -1 || endIdx == -1 {
		t.Fatalf("markers missing")
	}
	disabledSection := after[startIdx:endIdx]
	if strings.Contains(disabledSection, "Host web-1") || strings.Contains(disabledSection, "Host misc") {
		t.Errorf("non-deploy hosts inside disabled section:\n%s", after)
	}

	// Gate: connect to a disabled host must be refused.
	if err := a.Connect("deploy-acq", nil); err == nil {
		t.Error("Connect to disabled host should fail")
	} else if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("Connect error should mention disabled group, got: %v", err)
	}

	// Gate: connect to an enabled host still works (exec fails on missing
	// ssh binary only in test env; here we assert no group error).
	l, err := a.loadAll()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ensureHostNotDisabled(l.Hosts, "web-1"); err != nil {
		t.Errorf("ensureHostNotDisabled(web-1): %v", err)
	}

	// State file should list the group.
	disabled, err := a.IsGroupDisabled("deploy")
	if err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Error("IsGroupDisabled(deploy) = false, want true")
	}

	// Enable again.
	if err := a.EnableGroup("deploy"); err != nil {
		t.Fatalf("EnableGroup: %v", err)
	}

	restored := configAfter(t, a)

	// Markers gone, blocks restored verbatim.
	if strings.Contains(restored, "sshm disabled") {
		t.Errorf("markers should be gone after enable:\n%s", restored)
	}
	if !strings.Contains(restored, "Host deploy-acq\n  HostName 192.168.1.10\n  User deploy\n") {
		t.Errorf("deploy-acq not restored verbatim:\n%s", restored)
	}
	if !strings.Contains(restored, "Host web-1") || !strings.Contains(restored, "Host misc") {
		t.Errorf("other hosts lost during cycle:\n%s", restored)
	}

	// Gate open again.
	l, err = a.loadAll()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ensureHostNotDisabled(l.Hosts, "deploy-acq"); err != nil {
		t.Errorf("ensureHostNotDisabled(deploy-acq) after enable: %v", err)
	}

	// State file cleaned up.
	disabled, err = a.IsGroupDisabled("deploy")
	if err != nil {
		t.Fatal(err)
	}
	if disabled {
		t.Error("IsGroupDisabled(deploy) = true after enable, want false")
	}
}

// TestDisableEnableTwice verifies two consecutive disable/enable cycles
// leave exactly one marker pair and the original bytes.
func TestDisableEnableTwice(t *testing.T) {
	a := newSetUpTestApp(t, groupFixture)

	for i := 0; i < 2; i++ {
		if err := a.DisableGroup("deploy"); err != nil {
			t.Fatalf("cycle %d DisableGroup: %v", i, err)
		}
		if err := a.EnableGroup("deploy"); err != nil {
			t.Fatalf("cycle %d EnableGroup: %v", i, err)
		}
	}

	restored := configAfter(t, a)
	if strings.Count(restored, "sshm disabled") != 0 {
		t.Errorf("marker residue after two cycles:\n%s", restored)
	}
	if !strings.Contains(restored, "Host deploy-eu\n  HostName 192.168.1.11\n  User deploy\n") {
		t.Errorf("verbatim block lost after two cycles:\n%s", restored)
	}
}

// TestDisableUnknownGroup checks error handling for unknown groups.
func TestDisableUnknownGroup(t *testing.T) {
	a := newSetUpTestApp(t, groupFixture)
	if err := a.DisableGroup("nope"); err == nil {
		t.Error("DisableGroup(unknown) should fail")
	}
	if err := a.EnableGroup("nope"); err == nil {
		t.Error("EnableGroup(unknown) should fail")
	}
	// Invalid names rejected before touching anything.
	if err := a.DisableGroup("bad name"); err == nil {
		t.Error("DisableGroup(name with space) should fail")
	}
}

// TestListGroupsState checks the group listing with disabled markers.
func TestListGroupsState(t *testing.T) {
	a := newSetUpTestApp(t, groupFixture)
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	states, err := a.ListGroupsState()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]groupState{}
	for _, gs := range states {
		found[gs.Group] = gs
	}
	gs, ok := found["deploy"]
	if !ok {
		t.Fatalf("deploy group missing from state: %+v", states)
	}
	if len(gs.Disabled) != 2 {
		t.Errorf("deploy disabled hosts = %v, want 2 entries", gs.Disabled)
	}
}

// TestCopyGate checks that Copy refuses disabled-group remote targets.
func TestCopyGate(t *testing.T) {
	a := newSetUpTestApp(t, groupFixture)
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	// rsync may not exist in the test environment, but the gate must fire
	// before the exec — expect the disabled-group error, not a LookPath one.
	err := a.Copy("/tmp/file", "deploy-acq:/tmp/file", "")
	if err == nil {
		t.Fatal("Copy to disabled host should fail")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("Copy error should mention disabled group, got: %v", err)
	}
}