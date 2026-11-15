package cli

// S3, the half that needs a test binary WITHOUT a home override: the lookup
// behind the Include text (config.HomeDir) is the passwd home, not $HOME. The
// app package's TestMain replaces the lookup, so it can only be observed here.
// This test reads no file: it compares two strings.

import (
	"os/user"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

// Not parallel and uses no newCLIEnv: it must run while no test's override is
// in effect (those restore the lookup in t.Cleanup before the next test).
func TestImplS3_HomeDirIsThePasswdHome(t *testing.T) {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skipf("no passwd home: %v", err)
	}
	t.Setenv("HOME", t.TempDir()) // ssh ignores $HOME; so must the lookup
	if got := config.HomeDir(); got != u.HomeDir {
		t.Errorf("config.HomeDir() = %q, want the passwd home %q", got, u.HomeDir)
	}
}
