package cli

// Review fix F1: `groups disable` / `groups enable` name the file the blocks
// really live in: the managed file in managed mode, the main file in legacy
// mode. These tests use the real root command against temp-dir fixtures.

import (
	"fmt"
	"strings"
	"testing"
)

const cliReviewManaged = cliManagedHeader + `
Host deploy-acq
  HostName 192.168.1.10

Host deploy-eu
  HostName 192.168.1.11
`

// cliLineStarting returns the first stderr line that starts with prefix.
func cliLineStarting(t *testing.T, stderr, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	t.Fatalf("no line starting with %q in stderr:\n%s", prefix, stderr)
	return ""
}

func TestGroupsDisableEnable_ManagedModeNamesTheManagedFile(t *testing.T) {
	e := newCLIEnv(t, "Include @M@\n\nHost misc\n  HostName 10.0.0.9\n", cliReviewManaged)

	_, stderr, err := runCLI(t, "groups", "disable", "deploy")
	if err != nil {
		t.Fatalf("groups disable: %v\n%s", err, stderr)
	}
	// Exact line: the main path ("<dir>/config") is a string prefix of the
	// managed path ("<dir>/config.d/sshm.conf"), so a Contains check proves nothing.
	want := fmt.Sprintf("group %q disabled — blocks commented out of %s", "deploy", e.managed)
	if got := cliLineStarting(t, stderr, "group "); got != want {
		t.Errorf("disable line = %q, want %q", got, want)
	}

	_, stderr, err = runCLI(t, "groups", "enable", "deploy")
	if err != nil {
		t.Fatalf("groups enable: %v\n%s", err, stderr)
	}
	want = fmt.Sprintf("group %q enabled — blocks restored in %s", "deploy", e.managed)
	if got := cliLineStarting(t, stderr, "group "); got != want {
		t.Errorf("enable line = %q, want %q", got, want)
	}
}

func TestGroupsDisableEnable_LegacyModeNamesTheMainFile(t *testing.T) {
	e := newCLIEnv(t, "Host deploy-acq\n  HostName 192.168.1.10\n\nHost deploy-eu\n  HostName 192.168.1.11\n", cliAbsent)

	_, stderr, err := runCLI(t, "groups", "disable", "deploy")
	if err != nil {
		t.Fatalf("groups disable: %v\n%s", err, stderr)
	}
	want := fmt.Sprintf("group %q disabled — blocks commented out of %s", "deploy", e.main)
	if got := cliLineStarting(t, stderr, "group "); got != want {
		t.Errorf("disable line = %q, want %q", got, want)
	}

	_, stderr, err = runCLI(t, "groups", "enable", "deploy")
	if err != nil {
		t.Fatalf("groups enable: %v\n%s", err, stderr)
	}
	want = fmt.Sprintf("group %q enabled — blocks restored in %s", "deploy", e.main)
	if got := cliLineStarting(t, stderr, "group "); got != want {
		t.Errorf("enable line = %q, want %q", got, want)
	}
}
