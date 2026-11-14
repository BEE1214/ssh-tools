# Plan: sshm-managed config via `Include`

Status: PROPOSAL, revision 2 (after independent review). Nothing implemented.
Written on `feat/tui` (TUI uncommitted).

## 1. Problem

`config.Write` re-serializes the whole file. On a hand-annotated `~/.ssh/config` it drops
comments inside host blocks, moves comments between hosts, reindents, collapses blank lines
(reproduced with the master CLI: `sshm edit <host> --user x`). The review found it is also
*semantically* lossy (see 3b). ARCHITECTURE.md promises surgical writes; the code does not
deliver them. The TUI inherits all of it.

## 2. Decision

sshm stops writing the user's `~/.ssh/config`. It owns one file, included from the main file:

```
# ~/.ssh/config  (hand-owned; one line added by `sshm setup`)
Include ~/.ssh/config.d/sshm.conf
...everything else untouched...
```

- Main file: hand-owned (and DevPod). sshm reads it. It is edited only by three explicit,
  backed-up, dry-run-first operations, all raw line operations (never `Write`):
  `setup` (insert one line), `import` (delete moved line ranges), `init` (the `Host *`
  defaults block, which must stay in the main file, see 3).
- `~/.ssh/config.d/sshm.conf`: owned by sshm, edited by **line patching**, not by
  re-serializing (revision 2, see 5-P2). Imported blocks keep their comments and every
  option line byte-for-byte; only the keys an edit touches change.
- Group disable/enable keeps working (markers) inside the managed file; the sidecar moves
  to `<managed path>.sshm-groups`. Per-group files: later, not here (group is a name-prefix
  heuristic, a rename would have to move blocks between files).

## 3. Verified facts (OpenSSH_10.6p1, `ssh -F <file> -G`, scratch dir, 2026-11-14)

| # | Case | Result |
|---|------|--------|
| 1 | `Include` first, then `Host *` (User fallback, Port 2200) | managed host: `user managed` (include wins), `port 2200` (filled from `Host *`) |
| 2 | `Host *` first, `Include` after | `user fallback`; first value wins, include loses |
| 3 | `Include` after `Host foo` | managed host NOT found: include is conditional on the preceding block |
| 4 | Missing file / empty glob | silently ignored |
| 5 | Unknown option in included file | hard error ("Bad configuration option"), breaks every ssh call using that config |
| 6 | Relative path | resolved against the real `~/.ssh` (passwd home), not the including file's dir |
| 7 | Include loop | "Too many recursive configuration includes" |
| 8 | Included file group/world-writable | "Bad owner or permissions", fatal |
| 9 | Global option in main after an Include whose last block is `Host m1` | applies to unrelated hosts: no scope leak out of the included file |
| 10 | `LocalForward` in both files | both accumulate (list options do not follow first-wins) |
| - | `$HOME` override | ssh ignores it (uses passwd home). Tests MUST use `ssh -F` + absolute Include paths |

Consequences:
- `Include` must precede the first `Host`/`Match` (case 3). `setup` inserts it at line 1.
- Managed values beat main-file `Host *` defaults (case 1). Intended; doctor warns when a
  host name is defined in both files.
- Cases 5, 8: a bad managed file bricks all ssh. Every write needs a post-write `ssh -G`
  check with automatic rollback.
- `Host *` defaults from `sshm init` stay in the main file: in the managed file they would
  precede all main-file hosts and override their specific values.
- `ssh -G` evaluates `Match exec` (runs the user's own commands). Verification is skipped,
  with a warning, when any loaded file contains `Match ... exec`.

### 3b. Facts about the current code (from review, verified where marked)

- Writer drops `Port 22` (`writer.go` ~127) [verified]: with `Host * Port 2200` in main an
  explicit `Port 22` on a managed host silently becomes 2200 (case 1).
- Parser keeps one value for `IdentityFile`/`CertificateFile`/`ProxyJump` and for unknown
  keys (`Extra` map): repeated lines overwrite each other [verified, `parser.go` ~285-292].
  `Key=value` lines are dropped.
- `LineEnd` is not reliable (set at blank-line termination only, `parser.go` ~206).
  Do not use it for deletion ranges; derive ranges from raw text.
- `InitDefaults` prepends `Host *` and saves the whole main file through `Write` [verified,
  `init.go` ~28-35].
- `IsWildcard` matches only `"*"`; `Host a b` is stored as the name `"a b"`.
- `Backup` fails if the file is missing; `AtomicWrite` replaces symlinks (`os.Rename`), which
  would de-symlink a dotfiles-managed config; temp/backup files land next to the target.
- `FindConfig` uses `$HOME`, ssh uses the passwd home.

## 4. Why not just line-patch the main file? (reviewer's counter-proposal)

Fair question. Line-patching alone fixes the comment bug with no ssh-semantics risk. But the
main file is hand-owned and edited by DevPod and by you on three machines; any tool write
there is a risk, and managed hosts become a separate, syncable file. Include also gives a
natural "what sshm owns" boundary for doctor. The plan keeps the reviewer's technique (line
patching) for the owned file, so both points are used.

## 5. Phases (each ends with `make test` + `go vet`; each independently shippable)

### P1: Read path follows Include (no write changes)
`config.Load(mainPath, managedPath)` returns every file reachable via `Include` (tilde, glob,
depth 16, cycle guard, missing = skipped, relative = passwd-home `~/.ssh`). Each
`domain.Host` gets `SourceFile`. All read commands and the TUI use the merged list.
Merged hosts are a distinct type (`Loaded`) that `app.save` cannot accept; only a
`ManagedFile` can be written. Edit/delete/duplicate/disable of a host in another file:
`host "x" is defined in <file>, which sshm does not manage (run 'sshm import')`.

```go
// internal/config/load.go
type File struct {
    Path    string
    Managed bool
    Cfg     *ConfigFile
}
type Loaded struct {
    Files []File         // in ssh evaluation order
    Hosts []domain.Host  // merged view, read-only
}
func Load(mainPath, managedPath string) (*Loaded, error)
func ExpandInclude(arg string) []string // ~ via passwd home, glob, relative -> ~/.ssh
```
Acceptance: differential test vs `ssh -F fixture -G <h>` for **scalar keys and list keys as
a union** (case 10); not full-output equality. Skipped if `ssh` is absent.

### P2: Managed-file writer = line patching + verified writes
The managed file is stored as ordered blocks, each with its verbatim `Raw` lines.
- Untouched block: emitted byte-for-byte.
- Edit: replace only the matching option line in place (keep indent, key casing, inline
  comment); a new key goes after the block's last option line with the block's indent; a
  removed key removes its line. Repeated keys (`IdentityFile` x2) are all preserved.
- Add: fresh canonical block. Delete: block range plus its leading comment lines.
- No `Port 22` special case in this path.

```go
type Block struct {
    Raw   []string // verbatim lines, incl. leading comments and inner comments
    Host  domain.Host // parsed view, used for reads only
}
func PatchOption(b *Block, key, value string) // in place; append if absent
func (a *App) saveManaged(m *config.ManagedFile) error {
    bak, err := config.BackupIfExists(a.managedPath) // dir outside config.d: ~/.ssh/sshm-backups/
    ...
    before := resolve(a.configPath, hostNames)        // ssh -G per concrete host name
    if err := config.AtomicWriteMode(real(a.managedPath), data, 0o600); err != nil { ... }
    after := resolve(a.configPath, hostNames)
    if !equalExcept(before, after, editedHost, editedKeys) {
        restore(bak); return fmt.Errorf("verification failed, rolled back: %w", diff)
    }
}
```
Verification is semantic (every untouched host resolves identically, the edited host
differs only in the edited keys), not just "parses". `real()` = EvalSymlinks.
Tests: (a) untouched blocks byte-equal after any edit; (b) edited block differs only on
the changed lines; (c) repeated keys, `Key=value`, `Port 22`, comments survive. Also
closes the `DeleteHost` disabled-group gate gap found in the TUI review.

### P3: `sshm setup` and `add` into the managed file
`setup` (opt-in, idempotent): create `config.d/` 0700, `sshm.conf` 0600 with header, insert
`Include ~/.ssh/config.d/sshm.conf` as line 1 of main (raw insert, backup, no
re-serialization). Idempotency recognises the `~`, absolute and glob forms of the same file
(a duplicate Include makes ssh read it twice and can double `LocalForward` binds). `add`
refuses with a hint when the Include is missing; it never edits main by itself.
`SSH_AUTH_CONFIG` override: managed path = `<dir of main>/config.d/sshm.conf`, absolute path
in the Include line (tests/CI); default case writes the `~/` form (portable across machines).
`init` (Host * defaults): raw line operation on main, not `Write`.

### P4: `sshm import` (dry-run default)
Moves plain `Host` blocks (not DevPod, not any pattern containing `*`/`?`/`!`/multi-pattern,
not `Match`) from main into managed. Blocks move as raw text. Ranges come from the raw text
(not `LineEnd`). Order: capture `before` -> write managed -> delete ranges from main ->
ensure Include (delete first so line numbers do not shift) -> `after`. Any difference ->
restore both files, print the diff, exit 1 (`--force` accepts). Example: a block that sat
*after* `Host *` and lost to its defaults would now win; the check catches this silent
behavior change. Dry run prints what would move and the equivalence verdict.

### P5: `sshm doctor`
Extends `validate`; report-only on the main file. Checks: Include missing / not before first
Host|Match / duplicate Include forms; managed file perms/owner (0600, ours); `$HOME` differs
from passwd home; `ssh -G` parses; host defined in both files; `Match exec` present
(verification skipped); existing validate rules; `Host *` hardening gaps. `--diff` previews,
`--fix` applies **safe** fixes to the managed file only (dedupe keys, IdentitiesOnly,
HashKnownHosts). Behavior-changing fixes (StrictHostKeyChecking, restricted Kex/Ciphers) need
per-item confirmation.

### P6: TUI
Show source file per host; unmanaged hosts read-only with the import hint. Merge `feat/tui`
after P1-P3 so every TUI save already goes through `saveManaged`.

## 6. Out of scope
Per-group files; `sshm fmt`; editing main beyond `setup`/`import`/`init`; Match-block
editing; non-OpenSSH clients that ignore `Include` (Paramiko, as far as I know).

## 7. Open questions for Adam
1. Command name: `sshm setup` vs folding into `sshm init` (`init` already means "Host * defaults")?
2. Single `sshm.conf` (recommended) vs `config.d/*.conf` glob? Glob = other tools may drop
   files too, less control over what sshm treats as writable. Backups/temp files must then
   live outside `config.d/` (this plan already puts backups in `~/.ssh/sshm-backups/`).
3. Ship `feat/tui` before P2 (list + connect only, editor disabled) or hold the whole PR?
4. `import` scope: everything movable, or explicit `import <group|host>`?
5. Group disable for hosts still in main: refuse with the import hint (recommended) or keep
   the legacy path?

## 8. Risks (ranked)
1. Silent semantic loss when rewriting (repeated keys, `Port 22`, `Key=value`): mitigated by
   line patching + semantic before/after verification, not by "does it parse".
2. Wrong lines deleted on import: ranges from raw text, delete-before-insert, backup,
   equivalence check with automatic restore.
3. Behavior change from first-value-wins ordering on import: equivalence check.
4. Bad syntax/perms in the managed file bricks all ssh: rollback is mandatory.
5. Tests that lean on `$HOME` hit the real `~/.ssh`: always `-F` + absolute paths; add a
   guard test that no test touches the real home.
6. Fixtures are committed: placeholders only (example.com, 10.0.0.x).

## 9. Review log
Independent review (separate Claude Code run, read-only, no ssh) found: LineEnd unreliable,
semantic loss in Write, `init` rewrites main, symlink/backup issues, accumulating options,
`Match exec` side effect, phase coupling P2/P3, sidecar path, passwd-home vs `$HOME`, and
proposed plain line patching as the simpler alternative. Hermes verified the writer/parser/init
claims and the scope-leak and accumulation behavior with `ssh -G`. Unverified: duplicate
Include double-binding (reasoned, not run).
