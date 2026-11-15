package app

// Extra I11b cases: a partly-interrupted import (some blocks already in the
// managed file, some not) and the dry run of an interrupted state.

import (
	"strings"
	"testing"
)

const resumeWebBlock = `# web servers
Host web-1
  HostName 10.0.0.1
  User alice
`

// resumeEnv: web-1 is already in the managed file byte for byte, db-1 is not.
func resumeEnv(t *testing.T) *mgEnv {
	t.Helper()
	managed := mgManagedHeader
	if !strings.HasSuffix(managed, "\n") {
		managed += "\n"
	}
	return newMgEnv(t, crashMain, managed+"\n"+resumeWebBlock)
}

func TestImplImport_ResumeMixedAppendsOnlyTheMissingBlocks(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := resumeEnv(t)
	before := mgSSHAll(t, e.main, crashHosts)

	res, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	if got := strings.Join(imNames(res), ","); got != "web-1,db-1" {
		t.Errorf("Move = %s, want web-1,db-1", got)
	}
	if !mgNoteHas(res.Notes, "resuming an interrupted import") {
		t.Errorf("Notes = %q, want the resume note", res.Notes)
	}
	main, managed := e.readMain(t), e.readManaged(t)
	for _, h := range []string{"web-1", "db-1"} {
		if n := hostLineCount(main, h); n != 0 {
			t.Errorf("main still defines %s (%d times):\n%s", h, n, main)
		}
		if n := hostLineCount(managed, h); n != 1 {
			t.Errorf("managed defines %s %d times, want 1:\n%s", h, n, managed)
		}
	}
	if strings.Count(managed, "# web servers") != 1 {
		t.Errorf("web-1's comment was duplicated:\n%s", managed)
	}
	mgRequireSameResolution(t, e.main, before)

	// Second run: nothing left.
	res, err = e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	if len(res.Move) != 0 || mgNoteHas(res.Notes, "resuming") {
		t.Errorf("second run: Move = %v, Notes = %q, want nothing to do", imNames(res), res.Notes)
	}
}

func TestImplImport_ResumeDryRunListsMovesAndNotesAndWritesNothing(t *testing.T) {
	t.Parallel()
	e := resumeEnv(t)
	before := e.snap(t)

	res, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)
	if got := strings.Join(imNames(res), ","); got != "web-1,db-1" {
		t.Errorf("Move = %s, want web-1,db-1", got)
	}
	if !mgNoteHas(res.Notes, "resuming an interrupted import") {
		t.Errorf("Notes = %q, want the resume note", res.Notes)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}
