package app

// W1 (PR #8 review): a `Host` line with an inline comment (`Host web-9 # prod
// box`). The parser keeps the raw argument text as domain.Host.Name, while the
// ownership code compares the clean pattern (hostKey). Snapshot is the
// presentation boundary: every HostEntry must carry the name a user types
// (`web-9`), and Included / ReadOnlyReason must be computed from that name.
//
// Fixtures live in t.TempDir() (newMgEnv); hosts and addresses are
// placeholders. The helpers of snapshot_managed_test.go are reused unchanged.

import (
	"strings"
	"testing"
)

const hkMain = `Include @M@
Include @D@/extra.conf

Host main-9 # legacy note
  HostName 10.0.0.19
  User mainuser
  IdentityFile /keys/main9
`

const hkManaged = `# Managed by sshm. Hosts in this file are edited by sshm.

# the commented one
Host web-9 # prod box
  # the web node
  HostName 10.0.0.91
  User alice
  Port 2222
  IdentityFile /keys/web9

Host plain-9
  HostName 10.0.0.92
  User bob
`

const hkExtra = `Host inc-9 # included note
  HostName 10.0.0.99
  User incuser
`

// hkLegacyMain is the legacy-mode variant: no Include of the managed file.
const hkLegacyMain = `Include @D@/extra.conf

Host main-9 # legacy note
  HostName 10.0.0.19
  User mainuser
`

func hkEnv(t *testing.T, mainBody, managedBody string) *mgEnv {
	t.Helper()
	e := newMgEnv(t, mainBody, managedBody)
	mgWrite(t, e.smgExtra(), hkExtra, 0o600)
	e.backdate(t)
	return e
}

// hkEntry returns the single entry named name; on failure it lists the names
// the snapshot does carry, so a raw "web-9 # prod box" is visible.
func hkEntry(t *testing.T, s Snapshot, name string) HostEntry {
	t.Helper()
	es := smgEntries(s, name)
	if len(es) != 1 {
		t.Fatalf("snapshot has %d entries named %q, want 1; entry names: %q", len(es), name, smgNames(s))
	}
	return es[0]
}

func TestHkW1_EntryNamesAreTheCleanPattern(t *testing.T) {
	t.Parallel()
	e := hkEnv(t, hkMain, hkManaged)
	s := smgSnapshot(t, e)
	for _, name := range []string{"web-9", "main-9", "inc-9", "plain-9"} {
		hkEntry(t, s, name)
	}
	for _, h := range s.Hosts {
		if strings.Contains(h.Name, "#") || strings.ContainsAny(h.Name, " \t") {
			t.Errorf("entry name %q holds the inline comment, want the clean pattern", h.Name)
		}
	}
	if len(s.Hosts) != 4 {
		t.Errorf("snapshot has %d hosts (%q), want 4", len(s.Hosts), smgNames(s))
	}
}

func TestHkW1_ReasonAndIncludedInManagedMode(t *testing.T) {
	t.Parallel()
	e := hkEnv(t, hkMain, hkManaged)
	s := smgSnapshot(t, e)
	type want struct {
		reason   string
		included bool
	}
	for name, w := range map[string]want{
		"web-9":   {"", true}, // in the managed file (itself an included file)
		"plain-9": {"", true},
		"main-9":  {smgImportMsg("main-9", e.main), false},
		"inc-9":   {smgIncludedMsg("inc-9", e.smgExtra()), true},
	} {
		h := hkEntry(t, s, name)
		if h.ReadOnlyReason != w.reason {
			t.Errorf("ReadOnlyReason(%s) = %q, want %q", name, h.ReadOnlyReason, w.reason)
		}
		if h.Included != w.included {
			t.Errorf("Included(%s) = %v, want %v", name, h.Included, w.included)
		}
	}
	// The reason names the host, not its comment.
	if r := hkEntry(t, s, "main-9").ReadOnlyReason; strings.Contains(r, "legacy note") || strings.Contains(r, "#") {
		t.Errorf("ReadOnlyReason(main-9) = %q, must not mention the comment", r)
	}
}

func TestHkW1_ReasonAndIncludedInLegacyMode(t *testing.T) {
	t.Parallel()
	e := hkEnv(t, hkLegacyMain, mgAbsent)
	s := smgSnapshot(t, e)
	if s.Managed {
		t.Fatal("fixture: legacy env reports Managed")
	}
	if h := hkEntry(t, s, "main-9"); h.ReadOnlyReason != "" || h.Included {
		t.Errorf("main-9: ReadOnlyReason=%q Included=%v, want \"\" / false", h.ReadOnlyReason, h.Included)
	}
	h := hkEntry(t, s, "inc-9")
	if want := smgLegacyIncludedMsg("inc-9", e.smgExtra()); h.ReadOnlyReason != want || !h.Included {
		t.Errorf("inc-9: ReadOnlyReason=%q Included=%v, want %q / true", h.ReadOnlyReason, h.Included, want)
	}
}

// Parity with EditHost, which takes the name a user types.
func TestHkW1_ParityWithEditHost(t *testing.T) {
	t.Parallel()
	e := hkEnv(t, hkMain, hkManaged)
	s := smgSnapshot(t, e)

	before := e.snap(t)
	if err := e.a.EditHost("web-9", map[string]string{"user": "alice"}); err != nil {
		t.Errorf("EditHost(web-9, no-op) = %v, want nil", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
	if r := hkEntry(t, s, "web-9").ReadOnlyReason; r != "" {
		t.Errorf("ReadOnlyReason(web-9) = %q, want \"\" (EditHost accepts it)", r)
	}

	err := e.a.EditHost("main-9", map[string]string{"user": "mainuser"})
	if err == nil {
		t.Fatal("EditHost(main-9) = nil, want the import refusal")
	}
	if got := hkEntry(t, s, "main-9").ReadOnlyReason; got != err.Error() {
		t.Errorf("ReadOnlyReason(main-9) = %q, want the text EditHost returns: %q", got, err.Error())
	}
	if want := smgImportMsg("main-9", e.main); err.Error() != want {
		t.Errorf("EditHost(main-9) = %q, want %q", err.Error(), want)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

// A real edit of the commented managed host touches only its User line.
func TestHkW1_EditKeepsTheCommentOnTheHostLine(t *testing.T) {
	t.Parallel()
	e := hkEnv(t, hkMain, hkManaged)
	mainBefore := e.readMain(t)
	if err := e.a.EditHost("web-9", map[string]string{"user": "root"}); err != nil {
		t.Fatalf("EditHost(web-9) = %v", err)
	}
	want := strings.Replace(e.sub(hkManaged), "  User alice\n", "  User root\n", 1)
	if got := e.readManaged(t); got != want {
		t.Errorf("managed file:\n%s\nwant:\n%s", got, want)
	}
	if got := e.readMain(t); got != mainBefore {
		t.Errorf("main file changed:\n%s", got)
	}
	if s := smgSnapshot(t, e); hkEntry(t, s, "web-9").User != "root" {
		t.Errorf("snapshot User(web-9) = %q, want root", hkEntry(t, s, "web-9").User)
	}
}
