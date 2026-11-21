package app

// Owner rules of doctor (D9: ssh refuses a key only when the current user owns
// it; D10: ssh refuses a config file owned by neither root nor the current
// user). A non-root test cannot chown, so the owner comes from the ownerOf seam,
// keyed on the file's base name.

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// fakeOwners makes ownerOf report owners by file base name; every other file
// keeps its real owner. It restores the seam on cleanup.
func fakeOwners(t *testing.T, owners map[string]int) {
	t.Helper()
	real := ownerOf
	ownerOf = func(fi os.FileInfo) (int, bool) {
		if uid, ok := owners[fi.Name()]; ok {
			return uid, true
		}
		return real(fi)
	}
	t.Cleanup(func() { ownerOf = real })
}

// foreignUID is a uid that is neither root nor the current user.
func foreignUID() int { return currentUID() + 12345 }

const ownerKeyHost = "Host a\n  IdentityFile @K@/id_a\n" + drHardened

func TestDoctorOwnerKeyOwnedByCurrentUserIsFlagged(t *testing.T) {
	e := newDrEnv(t, ownerKeyHost, mgAbsent)
	e.key(t, "id_a", 0o644)
	fakeOwners(t, map[string]int{"id_a": currentUID()})
	drWantN(t, e.run(t, false), RuleUnsafePermissions, 1)
}

func TestDoctorOwnerKeyOwnedByOtherUserIsNotFlagged(t *testing.T) {
	e := newDrEnv(t, ownerKeyHost, mgAbsent)
	e.key(t, "id_a", 0o644)
	fakeOwners(t, map[string]int{"id_a": foreignUID()})
	drNoRule(t, e.run(t, false), RuleUnsafePermissions)
}

func TestDoctorOwnerKeyOwnedByRootIsNotFlagged(t *testing.T) {
	if currentUID() == 0 {
		t.Skip("running as root: uid 0 is the current user")
	}
	e := newDrEnv(t, ownerKeyHost, mgAbsent)
	e.key(t, "id_a", 0o644)
	fakeOwners(t, map[string]int{"id_a": 0})
	drNoRule(t, e.run(t, false), RuleUnsafePermissions)
}

func TestDoctorOwnerKeyMode0600ForeignOwnerNoFinding(t *testing.T) {
	e := newDrEnv(t, ownerKeyHost, mgAbsent)
	e.key(t, "id_a", 0o600)
	fakeOwners(t, map[string]int{"id_a": foreignUID()})
	drNoRule(t, e.run(t, false), RuleUnsafePermissions)
}

func TestDoctorOwnerKeyUnknownOwnerFallsBackToMode(t *testing.T) {
	e := newDrEnv(t, ownerKeyHost, mgAbsent)
	e.key(t, "id_a", 0o644)
	real := ownerOf
	ownerOf = func(fi os.FileInfo) (int, bool) {
		if fi.Name() == "id_a" {
			return 0, false
		}
		return real(fi)
	}
	t.Cleanup(func() { ownerOf = real })
	drWantN(t, e.run(t, false), RuleUnsafePermissions, 1)
}

func TestDoctorOwnerConfigForeignOwnerIsError(t *testing.T) {
	e := newDrEnv(t, "Host a\n  HostName example.invalid\n"+drHardened, mgAbsent)
	fakeOwners(t, map[string]int{"config": foreignUID()})
	got := drWantN(t, e.run(t, false), RuleUnsafePermissions, 1)
	if len(got) == 1 {
		m := got[0].Message
		if !strings.Contains(m, e.main) || !strings.Contains(m, strconv.Itoa(foreignUID())) ||
			!strings.Contains(m, "root") || !strings.Contains(m, strconv.Itoa(currentUID())) {
			t.Errorf("message must name the file, its owner uid and the allowed owners, got: %s", m)
		}
		if strings.Contains(m, "has mode") {
			t.Errorf("mode 0600 is fine, the message must not blame the mode: %s", m)
		}
	}
}

func TestDoctorOwnerConfigRootOwnerNoFinding(t *testing.T) {
	e := newDrEnv(t, "Host a\n  HostName example.invalid\n"+drHardened, mgAbsent)
	fakeOwners(t, map[string]int{"config": 0})
	drNoRule(t, e.run(t, false), RuleUnsafePermissions)
}

func TestDoctorOwnerConfigCurrentOwnerLooseModeKeepsMessage(t *testing.T) {
	e := newDrEnv(t, "Host a\n  HostName example.invalid\n"+drHardened, mgAbsent)
	if err := os.Chmod(e.main, 0o664); err != nil {
		t.Fatal(err)
	}
	fakeOwners(t, map[string]int{"config": currentUID()})
	got := drWantN(t, e.run(t, false), RuleUnsafePermissions, 1)
	if len(got) == 1 {
		want := "config file " + e.main + " has mode 0664: writable by group/other, ssh may refuse it (chmod 600 " + e.main + ")"
		if got[0].Message != want {
			t.Errorf("message changed:\n got  %s\n want %s", got[0].Message, want)
		}
	}
}

func TestDoctorOwnerConfigForeignOwnerAndLooseModeOneFinding(t *testing.T) {
	e := newDrEnv(t, "Host a\n  HostName example.invalid\n"+drHardened, mgAbsent)
	if err := os.Chmod(e.main, 0o664); err != nil {
		t.Fatal(err)
	}
	fakeOwners(t, map[string]int{"config": foreignUID()})
	got := drWantN(t, e.run(t, false), RuleUnsafePermissions, 1)
	if len(got) == 1 {
		m := got[0].Message
		if !strings.HasPrefix(m, "config file "+e.main+" has mode 0664") || !strings.Contains(m, strconv.Itoa(foreignUID())) {
			t.Errorf("want mode text prefix and the owner in one message, got: %s", m)
		}
	}
}
