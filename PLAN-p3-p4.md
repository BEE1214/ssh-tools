# Plan: P3 `sshm setup` + routing, P4 `sshm import`

Status: SPEC DRAFT for review. Nothing implemented. Follows `PLAN-include.md` (decisions section 7) and
the split pipeline (`contract-first-agent-split`): spec -> API skeleton -> test agent -> implementation
agent -> verify -> mutation audit.

## 1. Terms

- **main file**: the user's ssh config (`FindConfig()`: `$SSH_AUTH_CONFIG` or `~/.ssh/config`). Hand-owned.
- **managed file**: `<dir of main>/config.d/sshm.conf`, owned by sshm (`App.ManagedPath()`).
- **managed mode**: the managed file is among the files `config.Load` reached through an UNCONDITIONAL
  Include (`managedIncluded` accepts it). Otherwise **legacy mode**: every command behaves exactly as today.
- Every write to the managed file goes through `saveManagedDoc` (backup in `sshm-backups/`, lock,
  `ssh -G` before/after verification, rollback, mode 0600).

## 2. Facts (verified with real ssh unless noted; see PLAN-include.md section 3)

| # | Fact |
|---|------|
| F1 | ssh ignores `$HOME`; tests use `ssh -F <file>` and ABSOLUTE Include paths. |
| F2 | An Include is unconditional only above the first `Host`/`Match` line (or directly after a bare `Host *` / `Match all`). |
| F3 | First value wins for scalars; managed values beat later main-file `Host *` defaults because the Include is first. |
| F4 | A syntax error or group/world-writable included file makes every ssh call fail. |
| F5 | Moving a block from below `Host *` to above it can change what ssh resolves (the block starts winning). Import must detect this. |
| F6 | `ssh -G` prints normalized values; `Match exec` runs commands (verification is skipped, never run, when present). |

## 3. `sshm setup` (idempotent)

`sshm setup [--dry-run]`. API: `App.Setup(SetupOptions{DryRun}) (SetupResult, error)`.

| ID | Clause |
|----|--------|
| S1 | Creates `<dir>/config.d` (0700) and `sshm.conf` (0600) with a two-line header comment (`# Managed by sshm...`). An existing `sshm.conf` is never truncated or rewritten. |
| S2 | Inserts exactly one `Include` line as LINE 1 of the main file. Every other byte of the main file is unchanged; a backup of the main file is written to `sshm-backups/`; file mode and symlink-ness of the main file are preserved. |
| S3 | Include text: `Include ~/.ssh/config.d/sshm.conf` iff the main file is `<passwd home>/.ssh/config`; otherwise `Include <absolute managed path>` (tests, `$SSH_AUTH_CONFIG`). |
| S4 | Second run changes nothing (bytes and mtimes of both files) and reports `AlreadySetUp`. |
| S5 | An existing UNCONDITIONAL Include of the managed file in any spelling (`~` or absolute) counts as set up. An existing CONDITIONAL one (below a Host/Match line) is an error that names the line and says to move it above the first Host/Match; nothing is changed. |
| S6 | Missing main file: created (0600) containing only the Include line; missing `~/.ssh` dir is created 0700. |
| S7 | Verification: `ssh -G` of every concrete host name plus a sentinel is identical before and after; any difference or ssh error restores the main file (and removes a newly created managed file/dir) and returns an error. Skipped with a note (`Notes`) when `ssh` is missing or any loaded file has a `Match ... exec` line. |
| S8 | Refuses (no change) when `config.Load` reports include warnings (an Include sshm cannot follow), via `trustLoaded`. |
| S9 | `--dry-run` prints the planned `Actions` and changes nothing (bytes+mtimes). |
| S10 | End to end: after `setup`, a host appended to the managed file resolves via `ssh -F <main> -G <host>`. |

CLI output (stderr, one line per action): `create <path> (0700)`, `create <path> (0600)`,
`insert Include line at line 1 of <main>`; already done: `already set up: <managed path> is included from <main>`;
dry run prefixes each line with `would `. Exit 0 on success/no-op, 1 on error.

## 4. Routing in managed mode

Methods: `AddHost`, `EditHost`, `DeleteHost`, `DuplicateHost`, `AddForward`, `ClearForwards`,
`RunForward(save)`, `ClearCertificateFile` (cert sign), `DisableGroup`, `EnableGroup`, `InitDefaults`.
Legacy mode: unchanged (existing tests keep passing).

| ID | Clause |
|----|--------|
| R1 | Legacy mode: all commands behave exactly as before this change. |
| R2 | `add`: appends a canonical block to the managed file via `Doc.AppendBlock`; the main file is byte-identical; the name must not exist in ANY loaded file. |
| R3 | `edit` of a managed host: only the targeted lines change (`Doc.SetOption`/`UnsetOption`; indentation, key casing and inline comments kept); all other bytes of every file are identical. Empty value unsets. `identityfile`/`certificatefile` edits replace the whole list. Uses `setPlan` so the value must show up in `ssh -G`. |
| R4 | `edit`/delete/duplicate/`forward --save|--clear`/cert clearing of a host NOT in the managed file returns `*UnmanagedHostError` and changes nothing (bytes+mtimes of all files, no backup created). `CanImport` is true when the host is in the main file. |
| R5 | `duplicate`: `Doc.DuplicateBlock`; source must be managed; the new name must not exist anywhere. |
| R6 | `delete`: `Doc.DeleteBlock` on the managed file. |
| R7 | Forwards: `forward --save` adds the spec with `Doc.AddOptionValue` (LocalForward/RemoteForward/DynamicForward), `--clear` removes them; `forward` without `--save` writes nothing and works for any host. |
| R8 | `cert sign` that writes `CertificateFile` goes to the managed file for managed hosts; hosts elsewhere get `*UnmanagedHostError` and the cert is not left half-applied. |
| R9 | Clearing `User`/`HostName`/`Port`/`ProxyJump`/`HostKeyAlias` of a managed host works when no token option (`ControlPath ... %C` etc.) is in effect; otherwise the save is rolled back with an error that contains `token` and `set a value instead or edit the file by hand`; files unchanged. |
| R10 | Groups (option A, PLAN-include.md section 7): `groups disable <g>` requires EVERY member of the group to live in the managed file; the error lists up to 3 offending hosts (`and N more`) with the `UnmanagedHostError` wording and, for main-file hosts, the import hint. A group split across files is refused as a whole. `groups enable <g>` refuses if any disabled block of the group is outside the managed file. In managed mode the sidecar is `<managed path>.sshm-groups`. disable then enable restores the managed file byte-for-byte; the main file is never touched. |
| R11 | `init` in managed mode appends the `Host *` block (same algorithm filtering as today) to the END of the MAIN file only when no `Host *` exists in any loaded file; all existing main bytes are unchanged and the result is verified (`ssh -G` parses). If a `Host *` exists, nothing changes and the message names `<file>:<line>` and says sshm does not rewrite it. |
| R12 | Read commands (`list`, `dump`, `validate`, `groups`, `search`, completion, `connect` lookup) behave identically in both modes. |
| R13 | Every managed write leaves a backup of the previous managed file in `sshm-backups/` (newest 20 kept) and the file at mode 0600; an edit ssh rejects is rolled back byte-for-byte. |
| R14 | In legacy mode the write commands (`add`, `edit`, `forward --save`/`--clear`, `cert sign`, `groups disable`/`enable`, `init`) print one stderr line after success: `hint: run 'sshm setup' to keep sshm-managed hosts in <managed path>`. Managed mode prints no hint. API: `App.SetupHint() string` returns the line, or `""` in managed mode; the CLI prints it. |

Fixed error strings: not set up -> `sshm is not set up: run 'sshm setup' first` (`ErrNotSetUp`);
unmanaged host -> `host "x" is defined in <file>, which sshm does not manage; run 'sshm import'` (main file)
or `host "x" is defined in <file> (included), which sshm does not manage` (other files).

## 5. `sshm import [--apply] [--force]` (dry run by default)

API: `App.Import(ImportOptions{Apply, Force}) (ImportResult, error)`.

| ID | Clause |
|----|--------|
| I1 | Requires managed mode, else `ErrNotSetUp`. Refuses when `config.Load` reports include warnings. |
| I2 | Without `--apply`: prints the plan, changes nothing (bytes+mtimes of all files, no backup), exit 0. |
| I3 | Movable: plain single-name `Host` blocks of the MAIN file (no `*?!` characters, not DevPod, not `Match`), plus marker-disabled blocks (moved WITH their markers). Stay, with these exact reasons: `wildcard or pattern`, `multiple patterns`, `DevPod block`, `Match block`, `defined in an included file`. Preamble, Include lines and comments not attached to a moved block stay. |
| I4 | With `--apply`: the moved blocks appear in the managed file verbatim (attached and inner comments included, byte for byte), in original order, separated by one blank line; the main file loses exactly those spans plus one adjacent blank separator; every other main byte is identical. |
| I5 | Equivalence: `ssh -G` of every concrete host name (moved and staying) plus a sentinel is identical before and after. On any difference both files are restored byte-for-byte, the differing lines are printed (`host: -old / +new`), exit 1 (`ErrNotEquivalent`). With `--force` the move stays and the diff is printed. |
| I6 | A host name already defined in the managed file: abort before any write, list the names (`ErrImportConflict`). `--force` does not override this. |
| I7 | When verification is unavailable (ssh missing / `Match exec`) `--apply` refuses (`ErrCannotVerify`) unless `--force`. |
| I8 | Second run: `nothing to import`, no changes. |
| I9 | Disabled groups: markers and the disabled state follow the blocks; sidecar entries for moved disabled groups move from `<main>.sshm-groups` to `<managed>.sshm-groups`; `groups` shows the same states before and after; `groups enable <g>` afterwards restores the original bytes. |
| I10 | Both files are backed up to `sshm-backups/` before the write; managed mode 0600; main file mode and symlink-ness preserved. |
| I11 | Write order: managed first, then main. If the main write fails the managed file is restored. A crash between the two steps leaves a host defined in both files, which ssh resolves identically (managed first) and `validate` reports as `dup-host-cross-file`. |
| I12 | Lost updates: if either file changes between planning and the write, abort with `ErrConflict`, nothing changed. |

Dry-run output (stdout):
```
would move 3 blocks from <main> to <managed>:
  web-1     lines 12-16
  web-2     lines 18-21   (disabled, group web)
  db-1      lines 23-27
staying in <main>:
  *         line 4    wildcard or pattern
  demo      line 30   DevPod block
run 'sshm import --apply' to perform the move
```
Apply output ends with `moved 3 blocks; ssh resolves every host identically` (exit 0).

### 5.1 Result semantics (resolves the skeleton review)
- `ImportStay.Line` is the 1-based line of the `Host`/`Match` line in `ImportStay.File` (new field `File string`: the main file, or the included file for `defined in an included file`). `ImportBlock.FromLine` is the first attached comment line, `ToLine` the last line of the block.
- `ImportBlock.Group` is set for every block that has a group (explicit `# group:` comment or name-prefix heuristic), `""` otherwise; the dry-run text shows the group only for disabled blocks.
- A line with more than one pattern is `multiple patterns` even if one of them is a wildcard (`Host a *`); a single pattern containing `*?!` is `wildcard or pattern`.
- `ImportResult.Checked` (new `bool`) is true only when the `ssh -G` comparison ran. A dry run never runs it: `Checked=false`, `Equivalent=false`, and a note `equivalence is checked when --apply runs`. `Equivalent` is meaningful only when `Checked`.
- `ImportResult.Diff` has two entries per differing `ssh -G` line, in order: `<host>: -<key> <old value>` then `<host>: +<key> <new value>` (a key that appears only before or only after yields just the `-` or `+` entry).

## 6. Example

main before: `Host *` (line 1) / `Host web-1` / `Host db-1`; after setup+import with `Host *` first:
the check reports `web-1: -user fallback / +user mainuser` (F5) and exits 1 unless `--force`.

## 7. Non-goals

doctor (P5), TUI editor re-enable (P6), per-group files, auto-moving `Host *`, `sshm unsetup`,
rewriting the main file beyond S2/R11/I4.

## 8. Decisions (Adam, 2026-11-14)
1. R14 hint in legacy mode: yes.
2. `import --force`: kept (prints the diff, the move proceeds).
3. R11: managed-mode `init` appends `Host *` to the end of the main file only when none exists, never touches an existing one.
4. `import` is a dry run by default; `setup` applies immediately and has `--dry-run`.

## 9. Process

1. Skeleton: signatures + sentinels (`app/setup.go`, `app/import.go`, `cli/setup.go`) via Claude Code, committed.
2. Test agent (fresh, Sonnet): black-box tests from this spec + skeleton, `ssh -G` as oracle; returns clause -> test table.
3. Red check by Hermes. 4. Implementation agent (fresh, Sonnet), frozen tests. 5. Hermes verifies.
6. Mutation-audit reviewer (fresh, Sonnet).
