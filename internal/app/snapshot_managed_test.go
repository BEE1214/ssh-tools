package app

// Black-box tests for P6 (PLAN-p6.md) at the app layer: clauses T1-T6.
// Snapshot.Managed / ManagedPath, HostEntry.ReadOnlyReason, a managed-aware
// CheckEdit, and CheckHostName / CheckNewHost over every loaded file.
//
// Fixtures live in t.TempDir() (via newMgEnv), Include paths are absolute and
// ssh is only ever called with -F. Hosts and addresses are placeholders.
// Tests marked "characterization" already pass against the skeleton.

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// smgMain is the main file of the managed fixture: the Include of the managed
// file is the FIRST line, a second file is included too, and the main file
// itself holds a plain host, a DevPod host and a Host * block.
const smgMain = `Include @M@
Include @D@/extra.conf

# notes in the main file
Host main-1
  HostName 10.0.0.9
  User mainuser
  IdentityFile /keys/main1

# DevPod Start other.devpod
Host other.devpod
  User root
  ProxyCommand "/usr/bin/devpod-cli" ssh --stdio --context default --user root other
  ForwardAgent yes
  StrictHostKeyChecking no
  LogLevel error
  HostKeyAlgorithms rsa-sha2-256
# DevPod End other.devpod

Host *
  ServerAliveInterval 30
`

// smgManagedBody holds the editable hosts, with comments that must survive.
const smgManagedBody = `# Managed by sshm. Hosts in this file are edited by sshm.

# primary web host
Host web-1
  # the web node
  HostName 10.0.0.1
  User alice
  Port 2222
  IdentityFile /keys/web1
  # keepalive for web-1
  ServerAliveInterval 40

Host web-*
  ServerAliveCountMax 5

Host db-1
  HostName 10.0.0.2
  User bob
  IdentityFile /keys/db1

Host nouser-1
  HostName 10.0.0.3
  IdentityFile /keys/n1

Host bare-1
  HostName 10.0.0.4
  User carol

# DevPod Start demo.devpod
Host demo.devpod
  User root
  ProxyCommand "/usr/bin/devpod-cli" ssh --stdio --context default --user root demo
  ForwardAgent yes
  StrictHostKeyChecking no
  LogLevel error
  HostKeyAlgorithms rsa-sha2-256
# DevPod End demo.devpod

Host old-1
  HostName 10.0.0.31
  IdentityFile /keys/old1

Host old-2
  HostName 10.0.0.32
  IdentityFile /keys/old2
`

const smgExtraBody = `Host inc-1
  HostName 10.0.0.70
  User incuser
  IdentityFile /keys/inc1

Host inc-2
  HostName 10.0.0.71
`

// smgLegacyMain is the same set of editable hosts without the Include of the
// managed file: everything lives in the main file (legacy mode).
const smgLegacyMain = `Include @D@/extra.conf

# primary web host
Host web-1
  # the web node
  HostName 10.0.0.1
  User alice
  Port 2222
  IdentityFile /keys/web1
  # keepalive for web-1
  ServerAliveInterval 40

Host db-1
  HostName 10.0.0.2
  User bob
  IdentityFile /keys/db1

Host bare-1
  HostName 10.0.0.4
  User carol

Host main-1
  HostName 10.0.0.9
  User mainuser
  IdentityFile /keys/main1

Host *
  ServerAliveInterval 30
`

func (e *mgEnv) smgExtra() string { return filepath.Join(e.dir, "extra.conf") }

// smgManagedEnv builds the managed fixture. With gate it disables the group
// "old" (old-1, old-2 live in the managed file), which needs ssh.
func smgManagedEnv(t *testing.T, gate bool) *mgEnv {
	t.Helper()
	e := newMgEnv(t, smgMain, smgManagedBody)
	mgWrite(t, e.smgExtra(), smgExtraBody, 0o600)
	if gate {
		mgNeedSSH(t)
		mgRequireNoErr(t, e.a.DisableGroup("old"))
	}
	e.backdate(t)
	return e
}

func smgLegacyEnv(t *testing.T) *mgEnv {
	t.Helper()
	e := newMgEnv(t, smgLegacyMain, mgAbsent)
	mgWrite(t, e.smgExtra(), smgExtraBody, 0o600)
	e.backdate(t)
	return e
}

func smgSnapshot(t *testing.T, e *mgEnv) Snapshot {
	t.Helper()
	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	return s
}

func smgEntries(s Snapshot, name string) []HostEntry {
	var out []HostEntry
	for _, h := range s.Hosts {
		if h.Name == name {
			out = append(out, h)
		}
	}
	return out
}

// smgOne returns the single entry of the named host.
func smgOne(t *testing.T, s Snapshot, name string) HostEntry {
	t.Helper()
	es := smgEntries(s, name)
	if len(es) != 1 {
		t.Fatalf("snapshot has %d entries for %q, want 1", len(es), name)
	}
	return es[0]
}

func smgNames(s Snapshot) []string {
	var out []string
	for _, h := range s.Hosts {
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out
}

// smgImportMsg is the spec's literal text of UnmanagedHostError{CanImport: true}.
func smgImportMsg(host, file string) string {
	return fmt.Sprintf("host %q is defined in %s, which sshm does not manage; run 'sshm import'", host, file)
}

// smgIncludedMsg is the text of UnmanagedHostError{CanImport: false}.
func smgIncludedMsg(host, file string) string {
	return (&UnmanagedHostError{Host: host, File: file, CanImport: false}).Error()
}

// smgLegacyIncludedMsg is the legacy include refusal of EditHost.
func smgLegacyIncludedMsg(host, file string) string {
	return fmt.Sprintf("host %q is defined in %s (included), which sshm cannot edit yet", host, file)
}

// smgOwnershipRefusal reports whether err is a "this file is not mine" refusal
// (managed or legacy wording), as opposed to success or any other failure.
func smgOwnershipRefusal(err error) bool {
	if err == nil {
		return false
	}
	var u *UnmanagedHostError
	if errors.As(err, &u) {
		return true
	}
	return strings.Contains(err.Error(), "which sshm cannot edit yet") ||
		strings.Contains(err.Error(), "which sshm does not manage")
}

// ---- T1 ----------------------------------------------------------------------

// T1: Snapshot.Managed equals ManagedActive() and Snapshot.ManagedPath equals
// ManagedPath(), in managed mode, in legacy mode and for lookalikes.
func TestSmgT1_SnapshotReportsManagedModeAndPath(t *testing.T) {
	t.Parallel()
	managedEnv := func(t *testing.T) *mgEnv { return smgManagedEnv(t, false) }
	cases := []struct {
		name        string
		env         func(t *testing.T) *mgEnv
		wantManaged bool
	}{
		{"managed mode", managedEnv, true},
		{"managed file present but empty", func(t *testing.T) *mgEnv {
			return newMgEnv(t, "Include @M@\n\nHost main-1\n  HostName 10.0.0.9\n", "")
		}, true},
		{"legacy: no Include of the managed file", smgLegacyEnv, false},
		{"legacy: managed file on disk but never included", func(t *testing.T) *mgEnv {
			return newMgEnv(t, "Host main-1\n  HostName 10.0.0.9\n", smgManagedBody)
		}, false},
		{"legacy: Include inside a Host block is conditional", func(t *testing.T) *mgEnv {
			return newMgEnv(t, "Host main-1\n  Include @M@\n  HostName 10.0.0.9\n", smgManagedBody)
		}, false},
		{"legacy: Include after a Host block is conditional", func(t *testing.T) *mgEnv {
			return newMgEnv(t, "Host main-1\n  HostName 10.0.0.9\n\nInclude @M@\n", smgManagedBody)
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := c.env(t)
			active, err := e.a.ManagedActive()
			mgRequireNoErr(t, err)
			if active != c.wantManaged {
				t.Fatalf("fixture: ManagedActive() = %v, want %v", active, c.wantManaged)
			}
			s := smgSnapshot(t, e)
			if s.Managed != active {
				t.Errorf("Snapshot.Managed = %v, want ManagedActive() = %v", s.Managed, active)
			}
			if want := e.a.ManagedPath(); want == "" || s.ManagedPath != want {
				t.Errorf("Snapshot.ManagedPath = %q, want ManagedPath() = %q (non-empty, also in legacy mode)", s.ManagedPath, want)
			}
			if want := filepath.Join(e.dir, "config.d", "sshm.conf"); s.ManagedPath != want {
				t.Errorf("Snapshot.ManagedPath = %q, want %q", s.ManagedPath, want)
			}
		})
	}
}

// T1/T7 source: running `sshm setup` (here: App.Setup) flips the next snapshot
// to managed without any other state, and ManagedPath stays the same.
func TestSmgT1_SnapshotFollowsSetup(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := smgLegacyEnv(t)
	before := smgSnapshot(t, e)
	if before.Managed {
		t.Fatal("fixture: legacy snapshot reports Managed")
	}
	if _, err := e.a.Setup(SetupOptions{}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	after := smgSnapshot(t, e)
	if !after.Managed {
		t.Error("Snapshot.Managed = false after Setup, want true")
	}
	if want := filepath.Join(e.dir, "config.d", "sshm.conf"); after.ManagedPath != want || before.ManagedPath != want {
		t.Errorf("ManagedPath before/after Setup = %q / %q, want %q", before.ManagedPath, after.ManagedPath, want)
	}
	// After setup nothing has been imported yet: every host is outside the
	// managed file and carries the import hint.
	for _, h := range after.Hosts {
		if h.ReadOnlyReason == "" {
			t.Errorf("host %q has no ReadOnlyReason right after Setup (nothing imported yet)", h.Name)
		}
	}
}

// ---- T2 ----------------------------------------------------------------------

// T2: in managed mode ReadOnlyReason is "" exactly for hosts defined in the
// managed file (wildcard, DevPod and gated ones included); everything else
// carries the UnmanagedHostError text.
func TestSmgT2_ManagedModeReasonsFollowTheFile(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, true)
	s := smgSnapshot(t, e)

	want := map[string]string{
		// defined in the managed file: editable location
		"web-1": "", "web-*": "", "db-1": "", "nouser-1": "", "bare-1": "",
		"demo.devpod": "",              // DevPod is not reflected in the reason
		"old-1":       "", "old-2": "", // gated is not reflected in the reason
		// defined only in the main file: import hint
		"main-1":       smgImportMsg("main-1", e.main),
		"other.devpod": smgImportMsg("other.devpod", e.main),
		"*":            smgImportMsg("*", e.main),
		// defined only in another included file: no import hint
		"inc-1": smgIncludedMsg("inc-1", e.smgExtra()),
		"inc-2": smgIncludedMsg("inc-2", e.smgExtra()),
	}
	if got := smgNames(s); len(got) != len(want) {
		t.Fatalf("fixture: snapshot hosts = %v, want the %d fixture hosts", got, len(want))
	}
	for name, reason := range want {
		if got := smgOne(t, s, name).ReadOnlyReason; got != reason {
			t.Errorf("ReadOnlyReason(%s) = %q, want %q", name, got, reason)
		}
	}
	// The gated flag itself is still reported separately.
	if !smgOne(t, s, "old-1").Gated || smgOne(t, s, "web-1").Gated {
		t.Error("fixture: gate state of old-1 / web-1 is wrong")
	}
}

// T2 negative: Included keeps its meaning (defined only in files other than
// the main file) and is independent of the reason, so managed-file hosts are
// Included yet have no ReadOnlyReason.
func TestSmgT2_IncludedFlagIsUnchangedAndIndependent(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, false)
	s := smgSnapshot(t, e)
	for name, wantIncluded := range map[string]bool{
		"web-1": true, "db-1": true, "inc-1": true, "main-1": false, "*": false, "other.devpod": false,
	} {
		if got := smgOne(t, s, name).Included; got != wantIncluded {
			t.Errorf("Included(%s) = %v, want %v", name, got, wantIncluded)
		}
	}
	if smgOne(t, s, "web-1").ReadOnlyReason != "" {
		t.Error("a managed-file host is Included but must not have a ReadOnlyReason")
	}
	if smgOne(t, s, "inc-1").ReadOnlyReason == "" {
		t.Error("an included-only host outside the managed file must have a ReadOnlyReason")
	}
}

// T2: with an empty managed file nothing is editable: every host has a reason,
// each one naming the right file.
func TestSmgT2_EmptyManagedFileLeavesEveryHostReadOnly(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, "Include @M@\nInclude @D@/extra.conf\n\nHost main-1\n  HostName 10.0.0.9\n", "")
	mgWrite(t, e.smgExtra(), smgExtraBody, 0o600)
	s := smgSnapshot(t, e)
	want := map[string]string{
		"main-1": smgImportMsg("main-1", e.main),
		"inc-1":  smgIncludedMsg("inc-1", e.smgExtra()),
		"inc-2":  smgIncludedMsg("inc-2", e.smgExtra()),
	}
	if got := smgNames(s); len(got) != len(want) {
		t.Fatalf("fixture: hosts = %v", got)
	}
	for name, reason := range want {
		if got := smgOne(t, s, name).ReadOnlyReason; got != reason {
			t.Errorf("ReadOnlyReason(%s) = %q, want %q", name, got, reason)
		}
	}
}

// T2: reading the snapshot writes nothing.
func TestSmgT2_SnapshotWritesNothing(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, false)
	before := e.snap(t)
	smgSnapshot(t, e)
	mgRequireUnchanged(t, before, e.snap(t))
}

// ---- T3 ----------------------------------------------------------------------

// T3: legacy mode: main-file hosts have no reason; an included-only host
// carries the legacy include refusal text EditHost returns.
func TestSmgT3_LegacyReasons(t *testing.T) {
	t.Parallel()
	e := smgLegacyEnv(t)
	s := smgSnapshot(t, e)
	want := map[string]string{
		"web-1": "", "db-1": "", "bare-1": "", "main-1": "", "*": "",
		"inc-1": smgLegacyIncludedMsg("inc-1", e.smgExtra()),
		"inc-2": smgLegacyIncludedMsg("inc-2", e.smgExtra()),
	}
	if got := smgNames(s); len(got) != len(want) {
		t.Fatalf("fixture: snapshot hosts = %v", got)
	}
	for name, reason := range want {
		if got := smgOne(t, s, name).ReadOnlyReason; got != reason {
			t.Errorf("ReadOnlyReason(%s) = %q, want %q", name, got, reason)
		}
	}
	// The text really is the one EditHost returns today.
	err := e.a.EditHost("inc-1", map[string]string{"user": "x"})
	if err == nil || err.Error() != smgLegacyIncludedMsg("inc-1", e.smgExtra()) {
		t.Fatalf("fixture: legacy EditHost refusal = %v", err)
	}
}

// ---- T4 ----------------------------------------------------------------------

// smgParity checks, for every non-gated, non-DevPod host of the snapshot, that
// ReadOnlyReason is "" iff EditHost(name, <no-op change>) does not return an
// ownership refusal, and equals that refusal's message otherwise. The no-op
// change sets User to the host's own current User (see the report: the
// managed writer writes nothing for an equal value and checks ownership
// first). When noWrite is set the call must leave every byte, mtime and
// directory entry alone.
func smgParity(t *testing.T, e *mgEnv, noWrite bool) (checked int) {
	t.Helper()
	s := smgSnapshot(t, e)
	for _, h := range s.Hosts {
		if h.Gated || h.Source == domain.SourceDevPod {
			continue
		}
		before := e.snap(t)
		err := e.a.EditHost(h.Name, map[string]string{"user": h.User})
		if noWrite {
			mgRequireUnchanged(t, before, e.snap(t))
		}
		checked++
		if smgOwnershipRefusal(err) {
			if h.ReadOnlyReason != err.Error() {
				t.Errorf("host %q: ReadOnlyReason = %q, want the refusal EditHost returns: %q", h.Name, h.ReadOnlyReason, err.Error())
			}
		} else if h.ReadOnlyReason != "" {
			t.Errorf("host %q: EditHost is not refused (err=%v) but ReadOnlyReason = %q", h.Name, err, h.ReadOnlyReason)
		}
	}
	return checked
}

func TestSmgT4_ParityWithEditHostInManagedMode(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, true)
	// 13 entries minus the gated old-1/old-2 and the two DevPod hosts.
	if n := smgParity(t, e, true); n != 9 {
		t.Errorf("parity checked %d hosts, want 9 (fixture changed?)", n)
	}
}

func TestSmgT4_ParityWithEditHostInLegacyMode(t *testing.T) {
	t.Parallel()
	e := smgLegacyEnv(t)
	// The legacy writer re-serializes the file on every save, so only the
	// ownership decision is compared here.
	if n := smgParity(t, e, false); n != 7 {
		t.Errorf("parity checked %d hosts, want 7 (fixture changed?)", n)
	}
}

// T4: the managed fixture's hosts whose reason is "" are really the ones
// EditHost accepts with a REAL change, and the ones with a reason are really
// refused with exactly that text (a stronger form of the no-op parity).
func TestSmgT4_ReasonIsExactlyWhatARealEditReturns(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := smgManagedEnv(t, false)
	s := smgSnapshot(t, e)
	for _, h := range s.Hosts {
		// Pattern blocks (Host * / web-*) are skipped: ssh -G cannot show a
		// per-pattern change, so the writer rolls a real edit of them back for
		// reasons unrelated to ownership.
		if h.Source == domain.SourceDevPod || strings.ContainsAny(h.Name, "*?") {
			continue
		}
		err := e.a.EditHost(h.Name, map[string]string{"user": "paritycheck"})
		switch {
		case h.ReadOnlyReason == "":
			if err != nil {
				t.Errorf("host %q has no reason but EditHost fails: %v", h.Name, err)
			}
		case err == nil || err.Error() != h.ReadOnlyReason:
			t.Errorf("host %q: EditHost error %v, want ReadOnlyReason %q", h.Name, err, h.ReadOnlyReason)
		}
	}
}

// ---- T5 ----------------------------------------------------------------------

type smgEditCase struct {
	name      string
	host      string
	changes   map[string]string
	mutate    func(h *domain.Host) // the same change applied by hand, for the oracle
	wantRules []string             // literal expectation, guards against a vacuous oracle
}

func smgEditCases() []smgEditCase {
	return []smgEditCase{
		{"StrictHostKeyChecking no", "web-1", map[string]string{"stricthostkeychecking": "no"},
			func(h *domain.Host) { h.StrictHostKeyChecking = "no" }, []string{"strict-no"}},
		{"identity cleared", "web-1", map[string]string{"identityfile": ""},
			func(h *domain.Host) { h.IdentityFile, h.IdentityFiles = "", nil }, []string{"missing-identity"}},
		{"no changes on a clean host", "web-1", map[string]string{}, func(h *domain.Host) {}, nil},
		{"unrelated change on a clean host", "db-1", map[string]string{"user": "other"},
			func(h *domain.Host) { h.User = "other" }, nil},
		{"identity set on a bare host", "bare-1", map[string]string{"identityfile": "/keys/bare1"},
			func(h *domain.Host) { h.IdentityFile, h.IdentityFiles = "/keys/bare1", []string{"/keys/bare1"} }, nil},
		{"no changes on a bare host", "bare-1", nil, func(h *domain.Host) {}, []string{"missing-identity"}},
	}
}

func smgRules(issues []domain.Issue) []string {
	var out []string
	for _, i := range issues {
		out = append(out, i.Rule)
	}
	sort.Strings(out)
	return out
}

func smgKey(issues []domain.Issue) []string {
	var out []string
	for _, i := range issues {
		out = append(out, fmt.Sprintf("%s|%v|%s|%s", i.HostName, i.Severity, i.Rule, i.Message))
	}
	return out
}

// smgCheckEditMatchesValidate runs the table against env e: CheckEdit must
// return what domain.Validate yields for the host after the same change.
func smgCheckEditMatchesValidate(t *testing.T, e *mgEnv) {
	t.Helper()
	s := smgSnapshot(t, e)
	for _, c := range smgEditCases() {
		t.Run(c.name, func(t *testing.T) {
			h := smgOne(t, s, c.host).Host
			c.mutate(&h)
			oracle := domain.Validate([]domain.Host{h})
			if got := smgRules(oracle); !reflect.DeepEqual(got, c.wantRules) && !(len(got) == 0 && len(c.wantRules) == 0) {
				t.Fatalf("fixture: oracle rules = %v, want %v", got, c.wantRules)
			}
			before := e.snap(t)
			issues, err := e.a.CheckEdit(c.host, c.changes)
			mgRequireNoErr(t, err)
			mgRequireUnchanged(t, before, e.snap(t))
			if !reflect.DeepEqual(smgKey(issues), smgKey(oracle)) && !(len(issues) == 0 && len(oracle) == 0) {
				t.Errorf("CheckEdit(%s, %v) = %v, want the issues of domain.Validate: %v", c.host, c.changes, smgKey(issues), smgKey(oracle))
			}
		})
	}
}

func TestSmgT5_CheckEditOnManagedHostsMatchesValidate(t *testing.T) {
	t.Parallel()
	smgCheckEditMatchesValidate(t, smgManagedEnv(t, false))
}

// T5 legacy: unchanged behaviour (characterization, passes on the skeleton).
func TestSmgT5_CheckEditLegacyMatchesValidate(t *testing.T) {
	t.Parallel()
	smgCheckEditMatchesValidate(t, smgLegacyEnv(t))
}

// T5: the issues of a managed-file host point at the host's own block (file
// and line as domain.Validate reports them for the loaded host).
func TestSmgT5_IssueLocationIsTheManagedBlock(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, false)
	s := smgSnapshot(t, e)
	h := smgOne(t, s, "web-1").Host
	h.StrictHostKeyChecking = "no"
	oracle := domain.Validate([]domain.Host{h})
	issues, err := e.a.CheckEdit("web-1", map[string]string{"stricthostkeychecking": "no"})
	mgRequireNoErr(t, err)
	if len(oracle) != 1 || oracle[0].File != e.managed || oracle[0].Line == 0 {
		t.Fatalf("fixture: oracle = %+v", oracle)
	}
	if !reflect.DeepEqual(issues, oracle) {
		t.Errorf("CheckEdit issues = %+v, want exactly %+v (Line and File included)", issues, oracle)
	}
}

// T5: a host outside the managed file gets the *UnmanagedHostError EditHost
// returns (same text), also for DevPod and wildcard blocks; an unknown host a
// not-found error. Nothing is written.
func TestSmgT5_CheckEditRefusesHostsOutsideTheManagedFile(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, false)
	before := e.snap(t)
	cases := []struct {
		host      string
		canImport bool
		file      string
	}{
		{"main-1", true, e.main},
		{"other.devpod", true, e.main}, // ownership is decided before DevPod
		{"*", true, e.main},
		{"inc-1", false, e.smgExtra()},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			changes := map[string]string{"user": "zed"}
			_, err := e.a.CheckEdit(c.host, changes)
			var u *UnmanagedHostError
			if !errors.As(err, &u) {
				t.Fatalf("CheckEdit(%s) error = %v, want *UnmanagedHostError", c.host, err)
			}
			if u.Host != c.host || u.File != c.file || u.CanImport != c.canImport {
				t.Errorf("error = %+v, want host=%s file=%s canImport=%v", *u, c.host, c.file, c.canImport)
			}
			editErr := e.a.EditHost(c.host, changes)
			if editErr == nil || editErr.Error() != err.Error() {
				t.Errorf("CheckEdit error %q differs from EditHost's %v", err, editErr)
			}
			if c.canImport && err.Error() != smgImportMsg(c.host, e.main) {
				t.Errorf("error text = %q, want %q", err, smgImportMsg(c.host, e.main))
			}
		})
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

func TestSmgT5_CheckEditUnknownHostIsNotFound(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, false)
	before := e.snap(t)
	issues, err := e.a.CheckEdit("nope-1", map[string]string{"user": "zed"})
	if err == nil || !strings.Contains(err.Error(), "not found") || smgOwnershipRefusal(err) {
		t.Errorf("CheckEdit(unknown) = %v, %v; want a not-found error", issues, err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

// T5: gate and DevPod refusals for managed-file hosts are the same as EditHost's.
func TestSmgT5_CheckEditKeepsGateAndDevPodRefusals(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, true)
	before := e.snap(t)
	for host, wantSub := range map[string]string{
		"old-1":       "disabled group",
		"demo.devpod": "managed by DevPod",
	} {
		changes := map[string]string{"user": "zed"}
		_, err := e.a.CheckEdit(host, changes)
		if err == nil || !strings.Contains(err.Error(), wantSub) || smgOwnershipRefusal(err) {
			t.Errorf("CheckEdit(%s) = %v, want an error containing %q", host, err, wantSub)
			continue
		}
		if editErr := e.a.EditHost(host, changes); editErr == nil || editErr.Error() != err.Error() {
			t.Errorf("CheckEdit(%s) error %q differs from EditHost's %v", host, err, editErr)
		}
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

// T5 legacy: the refusals stay what they were (characterization).
func TestSmgT5_CheckEditLegacyRefusals(t *testing.T) {
	t.Parallel()
	e := smgLegacyEnv(t)
	before := e.snap(t)
	_, err := e.a.CheckEdit("inc-1", map[string]string{"user": "zed"})
	if err == nil || err.Error() != smgLegacyIncludedMsg("inc-1", e.smgExtra()) {
		t.Errorf("CheckEdit(inc-1) = %v, want %q", err, smgLegacyIncludedMsg("inc-1", e.smgExtra()))
	}
	if _, err := e.a.CheckEdit("nope-1", nil); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("CheckEdit(unknown) = %v, want not found", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

// ---- T6 ----------------------------------------------------------------------

// T6: a name defined in ANY loaded file exists; a fresh name does not.
// Characterization: loadAll based, passes on the skeleton.
func TestSmgT6_NamesInAnyLoadedFileExist(t *testing.T) {
	t.Parallel()
	for mode, mk := range map[string]func(*testing.T) *mgEnv{
		"managed": func(t *testing.T) *mgEnv { return smgManagedEnv(t, false) },
		"legacy":  smgLegacyEnv,
	} {
		t.Run(mode, func(t *testing.T) {
			e := mk(t)
			before := e.snap(t)
			existing := []string{"web-1", "db-1", "main-1", "inc-1", "inc-2"} // managed file / main file / other file
			for _, name := range existing {
				err := e.a.CheckHostName(name)
				if err == nil || !strings.Contains(err.Error(), "already exists") {
					t.Errorf("CheckHostName(%q) = %v, want an 'already exists' error", name, err)
				}
				issues, err := e.a.CheckNewHost(domain.Host{Name: name, HostName: "10.0.0.99", IdentityFile: "/keys/new"})
				mgRequireNoErr(t, err)
				found := false
				for _, i := range issues {
					if i.Rule == "host-name" && i.Severity == domain.SeverityError && strings.Contains(i.Message, "already exists") {
						found = true
					}
				}
				if !found {
					t.Errorf("CheckNewHost(%q) issues %v lack the duplicate-name error", name, smgKey(issues))
				}
			}
			for _, name := range []string{"new-1", "web-2", "inc-3"} {
				if err := e.a.CheckHostName(name); err != nil {
					t.Errorf("CheckHostName(%q) = %v, want nil", name, err)
				}
				issues, err := e.a.CheckNewHost(domain.Host{Name: name, HostName: "10.0.0.99", IdentityFile: "/keys/new"})
				mgRequireNoErr(t, err)
				if len(issues) != 0 {
					t.Errorf("CheckNewHost(%q) = %v, want no issues", name, smgKey(issues))
				}
			}
			if err := e.a.CheckHostName("two words"); err == nil {
				t.Error("CheckHostName with whitespace must still fail")
			}
			mgRequireUnchanged(t, before, e.snap(t))
		})
	}
}

// T6 (managed only): a managed-mode gated host name and a DevPod name are
// taken as well.
func TestSmgT6_GatedAndDevPodNamesExist(t *testing.T) {
	t.Parallel()
	e := smgManagedEnv(t, true)
	for _, name := range []string{"old-1", "demo.devpod", "other.devpod"} {
		if err := e.a.CheckHostName(name); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("CheckHostName(%q) = %v, want 'already exists'", name, err)
		}
	}
}
