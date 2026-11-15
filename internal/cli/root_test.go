package cli

import (
	"io"
	"strings"
	"testing"
)

// TestNoArgsWithoutTTY: bare `sshm` must refuse to launch the TUI when
// stdin/stdout is not a terminal, with a clear error (not the old
// "not yet implemented" text).
func TestNoArgsWithoutTTY(t *testing.T) {
	old := stdioIsTerminal
	stdioIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdioIsTerminal = old })

	root := NewRootCmd()
	root.SetArgs(nil)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error without a TTY")
	}
	if err.Error() != "sshm: no TTY; use 'sshm list'" {
		t.Errorf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "not yet implemented") {
		t.Error("stale 'not yet implemented' message")
	}
}

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
