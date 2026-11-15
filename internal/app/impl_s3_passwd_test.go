package app

// S3 (PLAN-p3-p4.md): the Include text is `Include ~/.ssh/config.d/sshm.conf`
// iff the main file is <passwd home>/.ssh/config, else an absolute path.
//
// includeLine is a pure function of the main path and config.HomeDir(); these
// tests never call Setup and never look at the real ~/.ssh. Every path below is
// under a temp dir: samePath resolves symlinks of the directory part, which
// would stat the real home if a real-home path were passed in.
//
// This package's TestMain replaces the home lookup (see guard_test.go), so the
// passwd-home lookup itself cannot be observed here; the test of that half is
// TestImplS3_HomeDirIsThePasswdHome in the cli package, whose test binary runs
// without an override.

import (
	"path/filepath"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

func TestImplS3_IncludeLineFollowsTheHomeLookup(t *testing.T) {
	t.Parallel()
	home := config.HomeDir()
	if home == "" || home != testHome {
		t.Fatalf("config.HomeDir() = %q, want the test override %q", home, testHome)
	}

	// The main file is <home>/.ssh/config: the "~" spelling.
	got := NewAppWithPath(filepath.Join(home, ".ssh", "config")).includeLine()
	if want := "Include ~/.ssh/config.d/sshm.conf"; got != want {
		t.Errorf("includeLine() for <home>/.ssh/config = %q, want %q", got, want)
	}
}

func TestImplS3_IncludeLineOutsideTheHomeIsAbsolute(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, main := range map[string]string{
		"temp dir":                  filepath.Join(dir, "config"),
		"~/.ssh but not the config": filepath.Join(config.HomeDir(), ".ssh", "other"),
		"under home, not in ~/.ssh": filepath.Join(config.HomeDir(), "config"),
		"another dir named .ssh":    filepath.Join(dir, ".ssh", "config"),
	} {
		got := NewAppWithPath(main).includeLine()
		want := "Include " + filepath.Join(filepath.Dir(main), "config.d", "sshm.conf")
		if got != want {
			t.Errorf("%s: includeLine() = %q, want %q", name, got, want)
		}
		if got == "Include ~/.ssh/config.d/sshm.conf" {
			t.Errorf("%s: got the ~ spelling for a main file that is not <home>/.ssh/config", name)
		}
	}
}
