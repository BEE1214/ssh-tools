package app

import (
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

func TestSnapshotMarksGatedHosts(t *testing.T) {
	a := newTestApp(t, groupFixture)
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	// Added after the group was disabled: not commented out, but gated via
	// the state file.
	if err := a.AddHost(domain.Host{Name: "deploy-new", HostName: "192.0.2.50"}); err != nil {
		t.Fatal(err)
	}

	snap, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	gated := map[string]bool{}
	for _, h := range snap.Hosts {
		gated[h.Name] = h.Gated
	}
	for name, want := range map[string]bool{
		"web-1": false, "misc": false,
		"deploy-acq": true, "deploy-eu": true, "deploy-new": true,
	} {
		got, ok := gated[name]
		if !ok {
			t.Errorf("host %q missing from snapshot", name)
		} else if got != want {
			t.Errorf("host %q Gated = %v, want %v", name, got, want)
		}
	}
	if len(snap.Issues) == 0 {
		t.Error("expected validation issues (missing identity) in snapshot")
	}
}

func TestCheckHostName(t *testing.T) {
	a := newTestApp(t, groupFixture)
	for name, wantErr := range map[string]bool{
		"":            true,
		"two words":   true,
		"web-1":       true, // exists
		"web-2":       false,
		"example-new": false,
	} {
		err := a.CheckHostName(name)
		if (err != nil) != wantErr {
			t.Errorf("CheckHostName(%q) err = %v, wantErr %v", name, err, wantErr)
		}
	}
}

func TestCheckNewHostAndEditDoNotWrite(t *testing.T) {
	a := newTestApp(t, groupFixture)
	before := configAfter(t, a)

	issues, err := a.CheckNewHost(domain.Host{Name: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !domain.HasErrors(issues) {
		t.Errorf("duplicate name should be an error, got %v", issues)
	}

	issues, err = a.CheckNewHost(domain.Host{Name: "web-9", IdentityFile: "~/.ssh/id_example"})
	if err != nil || domain.HasErrors(issues) || len(issues) != 0 {
		t.Errorf("clean new host: issues=%v err=%v", issues, err)
	}

	issues, err = a.CheckEdit("web-1", map[string]string{"stricthostkeychecking": "no"})
	if err != nil {
		t.Fatal(err)
	}
	var strict bool
	for _, i := range issues {
		if i.Rule == "strict-no" {
			strict = true
		}
	}
	if !strict {
		t.Errorf("expected strict-no warning, got %v", issues)
	}

	if _, err := a.CheckEdit("nope", nil); err == nil {
		t.Error("CheckEdit on unknown host should fail")
	}

	if after := configAfter(t, a); after != before {
		t.Error("Check* must not modify the config file")
	}
}

func TestCheckEditRefusesDisabledHost(t *testing.T) {
	a := newTestApp(t, groupFixture)
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CheckEdit("deploy-acq", map[string]string{"user": "x"}); err == nil {
		t.Error("CheckEdit on a disabled host should fail")
	}
}
