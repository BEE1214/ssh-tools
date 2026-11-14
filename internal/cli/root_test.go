package cli

import "testing"

// TestGroupsCommandsNotOnRoot: disable/enable live under `groups` only; a
// duplicate top-level registration would create `sshm disable` / `sshm enable`.
func TestGroupsCommandsNotOnRoot(t *testing.T) {
	root := NewRootCmd()

	for _, c := range root.Commands() {
		if c.Name() == "disable" || c.Name() == "enable" {
			t.Errorf("%q must not be a root subcommand", c.Name())
		}
	}

	var groups bool
	for _, c := range root.Commands() {
		if c.Name() != "groups" {
			continue
		}
		groups = true
		have := map[string]bool{}
		for _, sub := range c.Commands() {
			have[sub.Name()] = true
		}
		for _, want := range []string{"disable", "enable"} {
			if !have[want] {
				t.Errorf("groups subcommand %q missing", want)
			}
		}
	}
	if !groups {
		t.Error("groups command missing from root")
	}
}
