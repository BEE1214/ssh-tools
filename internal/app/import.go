package app

import (
	"errors"
	"path/filepath"
)

// managedPathFor returns the managed file that belongs to the main ssh config
// main: <dir of main>/config.d/sshm.conf.
func managedPathFor(main string) string {
	return filepath.Join(filepath.Dir(main), "config.d", "sshm.conf")
}

var (
	// ErrImportConflict: a host name to move is already defined in the managed
	// file. Raised before any write; --force does not override it (I6).
	ErrImportConflict = errors.New("import conflict: host already exists in the managed file")

	// ErrNotEquivalent: `ssh -G` resolves some host differently after the move.
	// Both files were restored unless --force was given (I5).
	ErrNotEquivalent = errors.New("import would change what ssh resolves")

	// ErrCannotVerify: ssh is missing or a loaded file has a 'Match ... exec'
	// line, so equivalence cannot be checked; --apply refuses unless --force
	// (I7).
	ErrCannotVerify = errors.New("cannot verify that the import preserves ssh behavior")
)

// Reasons a host block stays in the main file (I3). The texts are fixed.
const (
	StayWildcard     = "wildcard or pattern"
	StayMultiPattern = "multiple patterns"
	StayDevPod       = "DevPod block"
	StayMatch        = "Match block"
	StayIncluded     = "defined in an included file"
)

// ImportOptions are the options of Import.
type ImportOptions struct {
	// Apply performs the move; without it Import only plans (I2).
	Apply bool
	// Force keeps the move although equivalence is violated or cannot be
	// verified (I5, I7). It never overrides ErrImportConflict (I6).
	Force bool
}

// ImportBlock is one block to move from the main file to the managed file.
type ImportBlock struct {
	Name     string
	Group    string // set for every grouped block (explicit group comment or name-prefix heuristic), else ""
	Disabled bool   // the block is marker-disabled and moves with its markers (I3, I9)
	FromLine int    // 1-based, inclusive, in the main file: first attached comment line
	ToLine   int    // last line of the block
}

// ImportStay is a host that stays where it is (I3).
type ImportStay struct {
	Name string
	// File is the file that contains the Host/Match line: the main file, or the
	// included file for StayIncluded.
	File   string
	Line   int    // 1-based line of the Host/Match line in File
	Reason string // one of the Stay* constants
}

// ImportResult is the plan and, with Apply, the outcome of Import.
type ImportResult struct {
	// Move lists the blocks to move, in original order (I4).
	Move []ImportBlock
	// Stay lists what stays in the main file or in included files (I3).
	Stay []ImportStay
	// Applied: the files were written (I4).
	Applied bool
	// Checked is true only when the `ssh -G` comparison ran; a dry run never
	// runs it.
	Checked bool
	// Equivalent: `ssh -G` of every concrete host is identical before and
	// after (I5). Meaningful only when Checked.
	Equivalent bool
	// Diff has two entries per differing `ssh -G` line (I5):
	// "<host>: -<key> <old>" then "<host>: +<key> <new>".
	Diff []string
	// Notes carries non-fatal remarks, e.g. skipped verification (I7).
	Notes []string
}

// Import moves the plain single-name Host blocks (and marker-disabled blocks)
// of the main file into the managed file (I1-I12). It plans only unless
// opts.Apply is set. Returns ErrNotSetUp in legacy mode, ErrConflict (I12) when
// a file changed between planning and the write.
func (a *App) Import(opts ImportOptions) (ImportResult, error) {
	return ImportResult{}, ErrNotImplemented
}
