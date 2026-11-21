package app

// P7 clauses M1-M3 and clarifications 10 and 11 (PLAN-p7.md): a write addressed
// by one pattern of a multi-pattern Host line, or by the whole line text,
// returns *MultiPatternError; a single-pattern block of that name wins; the
// Snapshot entry carries the same text as ReadOnlyReason.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

const mpMain = `Include @M@
Include @D@/extra.conf

Host mm-1 mm-2
  HostName 10.0.2.1

Host mc-1 mc-2 # pair
  HostName 10.0.2.2

Host dup-1 dup-2
  HostName 10.0.2.3

Host dup-5
  HostName 10.0.2.5

Host dup-9
  HostName 10.0.2.9

Host dup-9 dup-10
  HostName 10.0.2.10
`

const mpManaged = mgManagedHeader + `
Host web-1
  HostName 10.0.0.1
  IdentityFile @D@/keys/web1

Host sign-1
  HostName 10.0.0.4
  IdentityFile @D@/keys/sign1

Host db-1 db-2
  HostName 10.0.2.20

Host dc-1 dc-2 # pair
  HostName 10.0.2.21

Host dup-1
  HostName 10.0.2.30

Host dup-3
  HostName 10.0.2.31

Host dup-3 dup-4
  HostName 10.0.2.32

Host dup-5 dup-6
  HostName 10.0.2.33

Host dup-7 dup-8
  HostName 10.0.2.34

Host sp-1   sp-2	# pair
  HostName 10.0.2.40

Host "a b" c
  HostName 10.0.2.41
`

const mpExtra = `Host ii-1 ii-2
  HostName 10.0.3.1

Host ic-1 ic-2 # pair
  HostName 10.0.3.2

Host dup-7
  HostName 10.0.3.3
`

func mpNew(t *testing.T) *mgEnv {
	t.Helper()
	e := nsNew(t, mpMain, mpManaged)
	mgWrite(t, filepath.Join(e.dir, "extra.conf"), mpExtra, 0o600)
	return e
}

// mpText is the text M1 fixes for the error and for ReadOnlyReason.
func mpText(name, file string) string {
	return fmt.Sprintf("%q in %s has several patterns, which sshm cannot edit", "Host "+name, file)
}

// mpRow is one multi-pattern line of the fixture. line is the Host line as
// written; block is its name (N1, PLAN-p7.md section 7 item 13): the patterns
// joined by ONE space, quotes and comment stripped.
type mpRow struct {
	name  string
	file  func(e *mgEnv) string
	line  string
	typed []string // the patterns, as a user types them
	block string
}

func mpRows() []mpRow {
	main := func(e *mgEnv) string { return e.main }
	managed := func(e *mgEnv) string { return e.managed }
	extra := func(e *mgEnv) string { return filepath.Join(e.dir, "extra.conf") }
	return []mpRow{
		{"main file", main, "Host mm-1 mm-2", []string{"mm-1", "mm-2"}, "mm-1 mm-2"},
		{"main file, comment", main, "Host mc-1 mc-2 # pair", []string{"mc-1", "mc-2"}, "mc-1 mc-2"},
		{"managed file", managed, "Host db-1 db-2", []string{"db-1", "db-2"}, "db-1 db-2"},
		{"managed file, comment", managed, "Host dc-1 dc-2 # pair", []string{"dc-1", "dc-2"}, "dc-1 dc-2"},
		{"included file", extra, "Host ii-1 ii-2", []string{"ii-1", "ii-2"}, "ii-1 ii-2"},
		{"included file, comment", extra, "Host ic-1 ic-2 # pair", []string{"ic-1", "ic-2"}, "ic-1 ic-2"},
		// rows 6 and 7 are only in the set-up fixture (mpManaged)
		{"managed file, extra spaces and a tab before the comment", managed, "Host sp-1   sp-2\t# pair", []string{"sp-1", "sp-2"}, "sp-1 sp-2"},
		{"managed file, quoted pattern", managed, `Host "a b" c`, []string{"a b", "c"}, "a b c"},
	}
}

// blockName returns the Name the parser gave the line, which must be r.block.
func (r mpRow) blockName(t *testing.T, e *mgEnv) (name, file string, line int) {
	t.Helper()
	file = r.file(e)
	line = mgLineOf(t, mgRead(t, file), r.line)
	h := nsHostByLine(t, e.a, file, line)
	name = h.Name
	if name != r.block {
		t.Fatalf("block of %q has Name %q, want %q", r.line, name, r.block)
	}
	if h.SourceFile == "" {
		t.Fatalf("host %q has no SourceFile", name)
	}
	return name, h.SourceFile, line
}

// mpCall is one write. emptyPath: the call ends in syscall.Exec when it gets
// that far (a bug), so PATH is emptied and it stops at "ssh not found" instead
// of replacing the test process.
type mpCall struct {
	name      string
	emptyPath bool
	call      func(e *mgEnv, host string) error
}

func mpCalls() []mpCall {
	chg := map[string]string{"user": "zed"}
	return []mpCall{
		{"EditHost", false, func(e *mgEnv, h string) error { return e.a.EditHost(h, chg) }},
		{"DuplicateHost", false, func(e *mgEnv, h string) error { return e.a.DuplicateHost(h, "copy-1") }},
		{"DeleteHost", false, func(e *mgEnv, h string) error { return e.a.DeleteHost(h) }},
		{"AddForward", false, func(e *mgEnv, h string) error {
			return e.a.AddForward(h, domain.ForwardLocal, []string{"8080:localhost:80"})
		}},
		{"ClearForwards", false, func(e *mgEnv, h string) error { return e.a.ClearForwards(h) }},
		{"ClearCertificateFile", false, func(e *mgEnv, h string) error { return e.a.ClearCertificateFile(h) }},
		{"CheckEdit", false, func(e *mgEnv, h string) error { _, err := e.a.CheckEdit(h, chg); return err }},
		{"RunForward with save", true, func(e *mgEnv, h string) error {
			return e.a.RunForward(h, domain.ForwardLocal, []string{"8080:localhost:80"}, true)
		}},
		{"SignCert", false, func(e *mgEnv, h string) error {
			_, err := e.a.SignCert(SignOpts{HostName: h, CAKey: filepath.Join(e.dir, "keys", "ca")})
			return err
		}},
	}
}

// M1 (+ clarification 11): every write addressed by one pattern, by the other
// pattern or by the whole line text returns *MultiPatternError with the fixed
// text, in the main file, the managed file and an included file, and it wins
// over the import hint (*UnmanagedHostError); nothing is written.
func TestMultiPattern_WritesReturnMultiPatternError(t *testing.T) {
	for _, row := range mpRows() {
		t.Run(row.name, func(t *testing.T) {
			e := mpNew(t)
			nsFakeKeygen(t)
			name, file, line := row.blockName(t, e)
			before := nsSnap(t, e.dir)
			typed := append(append([]string{}, row.typed...), name)
			for _, host := range typed {
				for _, c := range mpCalls() {
					t.Run(fmt.Sprintf("%s(%q)", c.name, host), func(t *testing.T) {
						if c.emptyPath {
							nsEmptyPath(t)
						}
						err := c.call(e, host)
						if err == nil {
							t.Fatal("got no error, want *MultiPatternError")
						}
						if errors.Is(err, ErrNotImplemented) {
							t.Fatalf("got ErrNotImplemented: %v", err)
						}
						var mp *MultiPatternError
						if !errors.As(err, &mp) {
							t.Fatalf("got %T %q, want *MultiPatternError", err, err)
						}
						var um *UnmanagedHostError
						if errors.As(err, &um) {
							t.Errorf("the import hint wins over the multi-pattern error: %v", err)
						}
						if mp.Host != name || mp.File != file || mp.Line != line {
							t.Errorf("MultiPatternError{Host:%q File:%q Line:%d}, want {%q %q %d}", mp.Host, mp.File, mp.Line, name, file, line)
						}
						if got, want := mp.Error(), mpText(name, file); got != want {
							t.Errorf("Error() = %q, want %q", got, want)
						}
						if got, want := err.Error(), mpText(name, file); !strings.Contains(got, want) {
							t.Errorf("returned error %q does not contain %q", got, want)
						}
						nsRequireSame(t, before, nsSnap(t, e.dir))
					})
				}
			}
		})
	}
}

// M1 with literal texts (not built by mpText): the block name is the patterns
// joined by one space, quotes and comment stripped (N1, item 13), so a comment,
// extra blanks, a tab or quotes never reach the message.
func TestMultiPattern_ErrorTextLiterals(t *testing.T) {
	e := mpNew(t)
	for _, c := range []struct{ typed, host string }{
		{"dc-1", "dc-1 dc-2"},
		{"dc-2", "dc-1 dc-2"},
		{"sp-2", "sp-1 sp-2"},
		{"c", "a b c"},
		{"a b c", "a b c"},
	} {
		err := e.a.EditHost(c.typed, map[string]string{"user": "zed"})
		want := `"Host ` + c.host + `" in ` + e.managed + ` has several patterns, which sshm cannot edit`
		var mp *MultiPatternError
		if !errors.As(err, &mp) {
			t.Errorf("EditHost(%q) = %v, want *MultiPatternError", c.typed, err)
			continue
		}
		if mp.Host != c.host || mp.Error() != want || !strings.Contains(err.Error(), want) {
			t.Errorf("EditHost(%q): Host=%q Error()=%q, want %q and %q", c.typed, mp.Host, mp.Error(), c.host, want)
		}
	}
}

// M1 for a line without comment: the block name is the argument text.
func TestMultiPattern_ErrorTextForPlainLine(t *testing.T) {
	e := mpNew(t)
	err := e.a.EditHost("db-1", map[string]string{"user": "zed"})
	want := `"Host db-1 db-2" in ` + e.managed + ` has several patterns, which sshm cannot edit`
	var mp *MultiPatternError
	if !errors.As(err, &mp) {
		t.Fatalf("got %v, want *MultiPatternError", err)
	}
	if mp.Error() != want || mp.Host != "db-1 db-2" || mp.Line != mgLineOf(t, e.readManaged(t), "Host db-1 db-2") {
		t.Errorf("got Host=%q Line=%d Error=%q, want db-1 db-2, its line, %q", mp.Host, mp.Line, mp.Error(), want)
	}
	// The same error for the same line, addressed by its whole text (M2).
	err2 := e.a.EditHost("db-1 db-2", map[string]string{"user": "zed"})
	if err2 == nil || err2.Error() != err.Error() {
		t.Errorf("whole line text gave %v, want the same error as the pattern: %v", err2, err)
	}
}

// M2 + clarification 10: a single-pattern block of the typed name is looked at
// first. In the managed file it is edited normally (also next to a multi-pattern
// line with the same pattern); elsewhere the unmanaged-host error wins. The whole
// line text of the multi-pattern line always gives *MultiPatternError.
func TestMultiPattern_SinglePatternBlockWins(t *testing.T) {
	chg := map[string]string{"user": "zed"}

	t.Run("single block in the managed file, multi-pattern line in the main file", func(t *testing.T) {
		e := mpNew(t)
		mainBefore := e.readMain(t)
		if err := e.a.EditHost("dup-1", chg); err != nil {
			t.Fatalf("EditHost(dup-1): %v", err)
		}
		if e.readMain(t) != mainBefore {
			t.Error("the main file changed")
		}
		if got := e.readManaged(t); !strings.Contains(got, "Host dup-1\n  HostName 10.0.2.30\n  User zed") {
			t.Errorf("the single block of the managed file was not edited:\n%s", got)
		}
		err := e.a.EditHost("dup-1 dup-2", chg)
		var mp *MultiPatternError
		if !errors.As(err, &mp) || mp.Host != "dup-1 dup-2" || mp.File != e.main {
			t.Errorf("EditHost(whole line) = %v, want *MultiPatternError for dup-1 dup-2 in %s", err, e.main)
		}
	})

	t.Run("single block and multi-pattern line both in the managed file", func(t *testing.T) {
		e := mpNew(t)
		if err := e.a.EditHost("dup-3", chg); err != nil {
			t.Fatalf("EditHost(dup-3): %v", err)
		}
		got := e.readManaged(t)
		if !strings.Contains(got, "Host dup-3\n  HostName 10.0.2.31\n  User zed") {
			t.Errorf("the single block was not edited:\n%s", got)
		}
		if !strings.Contains(got, "Host dup-3 dup-4\n  HostName 10.0.2.32\n\n") {
			t.Errorf("the multi-pattern block changed:\n%s", got)
		}
		if err := e.a.AddForward("dup-3", domain.ForwardLocal, []string{"8081:localhost:81"}); err != nil {
			t.Errorf("AddForward(dup-3): %v", err)
		} else if !strings.Contains(e.readManaged(t), "Host dup-3\n  HostName 10.0.2.31\n  User zed\n  LocalForward 8081 localhost:81") {
			t.Errorf("forward not in the single block:\n%s", e.readManaged(t))
		}
		var mp *MultiPatternError
		if err := e.a.EditHost("dup-3 dup-4", chg); !errors.As(err, &mp) || mp.Host != "dup-3 dup-4" {
			t.Errorf("EditHost(whole line) = %v, want *MultiPatternError", err)
		}
		if err := e.a.DeleteHost("dup-3"); err != nil {
			t.Fatalf("DeleteHost(dup-3): %v", err)
		}
		after := e.readManaged(t)
		if strings.Contains(after, "Host dup-3\n") || !strings.Contains(after, "Host dup-3 dup-4\n") {
			t.Errorf("DeleteHost(dup-3) must remove the single block only:\n%s", after)
		}
	})

	t.Run("single block in the main file wins over a multi-pattern line in the managed file", func(t *testing.T) {
		e := mpNew(t)
		before := nsSnap(t, e.dir)
		err := e.a.EditHost("dup-5", chg)
		var um *UnmanagedHostError
		if !errors.As(err, &um) || um.Host != "dup-5" || !um.CanImport || um.File != e.main {
			t.Fatalf("EditHost(dup-5) = %v, want *UnmanagedHostError for the main file with CanImport", err)
		}
		var mp *MultiPatternError
		if errors.As(err, &mp) {
			t.Errorf("must not be a MultiPatternError: %v", err)
		}
		nsRequireSame(t, before, nsSnap(t, e.dir))
		if err := e.a.EditHost("dup-5 dup-6", chg); !errors.As(err, &mp) || mp.File != e.managed {
			t.Errorf("EditHost(whole line) = %v, want *MultiPatternError in the managed file", err)
		}
	})

	t.Run("single block in an included file wins over a multi-pattern line in the managed file", func(t *testing.T) {
		e := mpNew(t)
		before := nsSnap(t, e.dir)
		err := e.a.DeleteHost("dup-7")
		var um *UnmanagedHostError
		if !errors.As(err, &um) || um.Host != "dup-7" || um.CanImport || filepath.Base(um.File) != "extra.conf" {
			t.Fatalf("DeleteHost(dup-7) = %v, want *UnmanagedHostError for extra.conf without CanImport", err)
		}
		nsRequireSame(t, before, nsSnap(t, e.dir))
	})

	t.Run("single block and multi-pattern line both in the main file", func(t *testing.T) {
		e := mpNew(t)
		before := nsSnap(t, e.dir)
		err := e.a.EditHost("dup-9", chg)
		var um *UnmanagedHostError
		if !errors.As(err, &um) || um.Host != "dup-9" || !um.CanImport {
			t.Fatalf("EditHost(dup-9) = %v, want the unmanaged-host error (import hint)", err)
		}
		var mp *MultiPatternError
		if err := e.a.EditHost("dup-9 dup-10", chg); !errors.As(err, &mp) || mp.Host != "dup-9 dup-10" {
			t.Errorf("EditHost(whole line) = %v, want *MultiPatternError", err)
		}
		nsRequireSame(t, before, nsSnap(t, e.dir))
	})
}

// M2 "After G3, M1 comes before not-found": a name that is only a pattern of a
// multi-pattern line is never reported as not found, and a name no line has
// still is.
func TestMultiPattern_BeforeNotFound(t *testing.T) {
	e := mpNew(t)
	err := e.a.DeleteHost("db-2")
	var mp *MultiPatternError
	if !errors.As(err, &mp) || strings.Contains(err.Error(), "not found") {
		t.Errorf("DeleteHost(db-2) = %v, want *MultiPatternError", err)
	}
	if err := e.a.DeleteHost("db-3"); err == nil || !strings.Contains(err.Error(), `host "db-3" not found`) || errors.As(err, &mp) {
		t.Errorf("DeleteHost(db-3) = %v, want 'not found'", err)
	}
}

// M3: Snapshot gives the entry of a multi-pattern line the M1 text as
// ReadOnlyReason, in the main, managed and included file, and it is the text
// EditHost returns (P6 T2/T4 parity). Single-pattern hosts are unaffected.
func TestMultiPattern_SnapshotReadOnlyReasonSetUp(t *testing.T) {
	e := mpNew(t)
	for _, row := range mpRows() {
		t.Run(row.name, func(t *testing.T) {
			name, file, _ := row.blockName(t, e)
			entry := nsEntry(t, e.a, name)
			if want := mpText(name, file); entry.ReadOnlyReason != want {
				t.Errorf("ReadOnlyReason = %q, want %q", entry.ReadOnlyReason, want)
			}
			err := e.a.EditHost(entry.Name, map[string]string{"user": "zed"})
			if err == nil || err.Error() != entry.ReadOnlyReason {
				t.Errorf("EditHost(%q) = %v, want the text of ReadOnlyReason (parity)", entry.Name, err)
			}
		})
	}
	t.Run("single-pattern hosts are unaffected", func(t *testing.T) {
		if got := nsEntry(t, e.a, "dup-3").ReadOnlyReason; got != "" {
			t.Errorf("single block dup-3 in the managed file: ReadOnlyReason %q, want empty", got)
		}
		um := &UnmanagedHostError{Host: "dup-5", File: e.main, CanImport: true}
		if got := nsEntry(t, e.a, "dup-5").ReadOnlyReason; got != um.Error() {
			t.Errorf("single block dup-5 in the main file: ReadOnlyReason %q, want %q", got, um.Error())
		}
		if got := nsEntry(t, e.a, "web-1").ReadOnlyReason; got != "" {
			t.Errorf("web-1: ReadOnlyReason %q, want empty", got)
		}
	})
}

// M3 "(both modes)": on a config that is not set up the entry of a multi-pattern
// line carries the M1 text too (in the main file and in an included file).
func TestMultiPattern_SnapshotReadOnlyReasonNotSetUp(t *testing.T) {
	main := "Include @D@/extra.conf\n\nHost mm-1 mm-2\n  HostName 10.0.2.1\n\nHost mc-1 mc-2 # pair\n  HostName 10.0.2.2\n\nHost single-1\n  HostName 10.0.2.4\n"
	e := nsNew(t, main, mgAbsent)
	mgWrite(t, filepath.Join(e.dir, "extra.conf"), mpExtra, 0o600)
	rows := []mpRow{mpRows()[0], mpRows()[1], mpRows()[4], mpRows()[5]}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			name, file, _ := row.blockName(t, e)
			entry := nsEntry(t, e.a, name)
			if want := mpText(name, file); entry.ReadOnlyReason != want {
				t.Errorf("ReadOnlyReason = %q, want %q", entry.ReadOnlyReason, want)
			}
		})
	}
	if got := nsEntry(t, e.a, "single-1").ReadOnlyReason; got != "" {
		t.Errorf("single-pattern host in the main file: ReadOnlyReason %q, want empty (unchanged)", got)
	}
}
