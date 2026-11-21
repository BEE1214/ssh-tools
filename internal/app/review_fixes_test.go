package app

// Review fix F2: retry safety of the managed-mode group disable. DisableGroup
// edits the managed file and THEN writes the sidecar; if the sidecar write
// failed, a retry used to fail with "has no enabled hosts" and never record the
// group. Fixtures live in temp dirs only.

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

const rfManaged = mgManagedHeader + `
Host deploy-acq
  HostName 192.168.1.10

Host deploy-eu
  HostName 192.168.1.11

Host web-1
  HostName 10.0.0.1
`

func TestDisableGroupManaged_RetryAfterFailedSidecarWriteRecordsTheGroup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		otherSide bool // the sidecar keeps another group when the "failure" happened
	}{
		{"sidecar file missing", false},
		{"sidecar keeps another group", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgNeedSSH(t)
			e := newMgEnv(t, "Include @M@\n", rfManaged)
			side := mgSidecar(e.managed)

			mgRequireNoErr(t, e.a.DisableGroup("deploy"))
			if tc.otherSide {
				// A second group is recorded and "deploy" is lost again: the
				// half-done state of a failed sidecar write.
				mgRequireNoErr(t, e.a.DisableGroup("web"))
				mgRequireNoErr(t, writeGroupState(side, map[string]bool{"web": true}))
			} else if err := os.Remove(side); err != nil {
				t.Fatal(err)
			}
			e.backdate(t)
			managedBytes := e.readManaged(t)
			if !strings.Contains(managedBytes, "# sshm disabled") {
				t.Fatalf("fixture error: deploy blocks are not disabled in the managed file:\n%s", managedBytes)
			}
			before := e.snap(t)

			// The retry: no Doc edit, the sidecar gets the group.
			mgRequireNoErr(t, e.a.DisableGroup("deploy"))
			if got := e.readManaged(t); got != managedBytes {
				t.Errorf("managed file changed on the retry:\n%s", got)
			}
			wantDiff := []string{"added " + side}
			if tc.otherSide {
				wantDiff = []string{"changed " + side}
			}
			if d := mgDiff(before, e.snap(t), false); !reflect.DeepEqual(d, wantDiff) {
				t.Errorf("changed files = %v, want only %v (managed file and main file untouched)", d, wantDiff)
			}
			state, err := readGroupStateFile(side)
			mgRequireNoErr(t, err)
			want := map[string]bool{"deploy": true}
			if tc.otherSide {
				want["web"] = true
			}
			if !reflect.DeepEqual(state, want) {
				t.Errorf("sidecar = %v, want %v", state, want)
			}

			// Second call: the sidecar records it now, so the old refusal stays.
			after := e.snap(t)
			err = e.a.DisableGroup("deploy")
			mgRequireErr(t, err)
			if !strings.Contains(err.Error(), `group "deploy" has no enabled hosts`) {
				t.Errorf("second DisableGroup error = %q, want the 'has no enabled hosts' refusal", err)
			}
			mgRequireUnchanged(t, after, e.snap(t))
		})
	}
}

func TestDisableGroupManaged_UnknownGroupStillFails(t *testing.T) {
	mgNeedSSH(t)
	e := newMgEnv(t, "Include @M@\n", rfManaged)
	before := e.snap(t)
	err := e.a.DisableGroup("nosuch")
	mgRequireErr(t, err)
	if !strings.Contains(err.Error(), "no enabled hosts") {
		t.Errorf("error = %q, want the 'has no enabled hosts' refusal", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
	if mgExists(mgSidecar(e.managed)) {
		t.Error("a sidecar was written for an unknown group")
	}
}
