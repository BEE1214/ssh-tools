# P7: retire legacy mode (spec, draft 1)

Phase P7 of `PLAN-include.md`. Branch `feat/legacy-retire`, stacked on `feat/tui-editor` (PR #8). Adam decided after P6 that
legacy mode goes once the TUI editor exists. The shape of this spec comes from a three-round adversarial review
(four Sonnet seats: users/migration, safety, architecture, compatibility/first run); the full bundle is
`p7-consensus-bundle.md` in Hermes scratch (fact #492). The review is input; the clauses below are the contract.

## 1. Scope
Every command that WRITES an ssh config requires the managed Include created by `sshm setup`. Without it the command
fails with `ErrNotSetUp`, changes nothing and does not run setup. The write code that re-serializes the main file
(`config.Write` and everything only it needs) is deleted. Read-only commands behave exactly as before.

## 2. Decisions (Adam, 2026-11-21)
1. Write commands without the managed Include: refuse with `ErrNotSetUp`, no auto-setup.
2. `sshm init` on a machine with no ssh config creates the managed setup with an EMPTY managed file (see I1); it does
   not write a `Host *` block there. The path is `~/.ssh/config.d/sshm.conf` (Adam wrote `sshm.config`; Hermes read
   that as the existing managed file name).
3. A host that is one pattern of a multi-pattern `Host` line gets a clear read-only reason instead of "not found".
4. A recovery path for a broken managed file is in scope. Hermes' choice of minimal mechanism (Adam may overrule):
   signal-safe rollback (R1) and a refusal message that names the newest backup (R2). Adam confirmed: no `restore`
   command for now, maybe later if it proves useful.
   Detecting an ssh-rejected config is `doctor` D20 (`ssh-rejects-config`, PR #7); it is not duplicated in `validate`.
5. `setup` gets no override and no `IgnoreUnknown` hint for configs that ssh itself rejects.
Not decided, therefore out of scope: OpenSSH 7.3 version check, documented recipes for read-only/symlinked dotfile
mains, advice for tools that do not follow `Include` (README notes only, see X5).

## 3. Facts (verified in the review, OpenSSH 10.6 unless noted)
- `writer.go` cannot be deleted whole: `Doc` needs `writeHostBlock`, `groupCommentFor`, `checkLineBreaks`, `sortedKeys`
  (`doc_raw.go` `BlockLines`, used by `Doc.AppendBlock` and `initManaged`).
- Read-side code that stays: `commentOutLine`, `uncommentLines`, `appendDisabledHosts`, `ensureInMainLoaded`,
  `groupStatePath`/`mainGroupStatePath`, `activeView`/`viewOf`/`ManagedActive`, `RawTextLines`.
- `hostKey` (routing.go) already is the user-visible name: one pattern -> that pattern, else the line's text.
- With no `~/.ssh/config`, every command except `setup` fails today with `read config: open <path>: no such file or directory`.
- Legacy write never verifies with ssh; managed write does, except with `Match ... exec` or no ssh binary.
- No signal handling exists; a SIGINT during the verify step leaves the bad write in the managed file, after which
  every sshm write is refused ("already broken") and no command restores the backup.

## 4. Clauses

### Gate
| ID | Clause |
|---|---|
| G1 | These return `ErrNotSetUp` (text `sshm is not set up: run 'sshm setup' first`, `errors.Is` works) when the main file has no unconditional Include of the managed file: `AddHost`, `EditHost`, `DeleteHost`, `DuplicateHost`, forward save/clear, `SignCert` with a host, `ClearCertificateFile`, `DisableGroup`, `EnableGroup`, `InitDefaults*` (except I1) and `CheckEdit`. Hence the CLI commands `add`, `edit`, `duplicate`, `forward --save/--clear`, `cert sign --host`, `cert revoke` (when a host references the cert), `groups disable/enable`, `init`, and the TUI edit keys. |
| G2 | The gate changes nothing: no file or directory under the ssh dir is created or modified (no lock file, no backup), and a refused `cert sign --host` neither runs `ssh-keygen` nor creates or overwrites a certificate; a refused `cert revoke` does not delete the certificate file. |
| G3 | The gate comes first: `ErrNotSetUp` wins over not-found, already-exists, unmanaged-host and multi-pattern errors. Argument errors that need no config (cobra flag errors) still come first. |
| G4 | Main file does not exist: every gated command except `init` returns `ErrNotSetUp` (not `read config: ...`). Any other read or parse error of the config keeps today's message. |
| G5 | `SetupHint` and the stderr hint `hint: run 'sshm setup' ...` after write commands are removed; a successful write prints nothing about setup. |
| G6 | Read-only commands (`list`, `search`, `dump`, `connect`/`sshm <host>`, `copy`, `validate`, `groups`, `cert list`, `cert inspect`, `cert revoke` without a referencing host, TUI browsing) behave as before on a config that is not set up, including the unchanged `read config: open ...` error when the main file does not exist. Characterization: green before and after. |
| G7 | TUI on a config that is not set up: unchanged from P6 T8 (toast `editing needs setup: run 'sshm setup' to create <ManagedPath>`; no banner is added). `CheckEdit` returning `ErrNotSetUp` never reaches the form. |

### Init on a fresh machine
| ID | Clause |
|---|---|
| I1 | `sshm init` when the MAIN FILE DOES NOT EXIST performs exactly the `sshm setup` actions (create the ssh dir 0700 if missing, `config.d` and `sshm.conf` 0600, main file containing the Include line; verified like setup) and stops there: the managed file stays empty (header only) and NO `Host *` block is written. Afterwards `ssh -F <main> -G <any host>` succeeds, `sshm list` prints nothing and exits 0, and `sshm validate` reports no error. This is the only gated command that sets up on its own. |
| I2 | Output of I1: the setup action lines exactly as `sshm setup` prints them (same stream), followed by one line telling the user that the empty managed file was created and that `sshm init` run again adds the default `Host *` block (wording fixed in the clarifications). |
| I3 | `init` on an existing main file that is not set up: `ErrNotSetUp` (G1), file untouched. `init` on a set-up config (including the one I1 just created): unchanged, i.e. it adds the default `Host *` block as before (R11 of PLAN-p3-p4: end of the main file, only if none exists). |
| I4 | Running `init` on a fresh machine twice gives: first run I1, second run the normal set-up `init` (adds `Host *`). A failure inside I1 leaves either the previous state or a complete set-up state, as `sshm setup` does. |

### Names and multi-pattern lines
| ID | Clause |
|---|---|
| N1 | `domain.Host.Name` produced by the parser is exactly what `hostKey` returns today: a `Host` line with one pattern (comment and quotes stripped, `Host web-1 # prod` -> `web-1`), otherwise the line's argument text unchanged. A literal `Host "a b"` versus `Host a b` collision is accepted as today. |
| N2 | `hostKey` and the name rewrite in `Snapshot` are removed (the name is already clean). `dump`, `connect`, `copy`, `edit`, `duplicate`, `delete`, `forward`, `cert`, group commands find `web-1` for `Host web-1 # prod`. |
| N3 | No regression (characterization): `Host * !x` is not a wildcard (`IsWildcard()` false); `Host a b` followed by `Host a` raises no `duplicate-host`; `Host # c` keeps its current name; `isConcreteName` results are unchanged; `Host web-1 # prod` is now concrete. |
| M1 | A write addressed by a name that is only one of several patterns of a `Host` line (`edit db-1` with `Host db-1 db-2 # pair`) returns `*MultiPatternError` with the text `"Host db-1 db-2" in <file> has several patterns, which sshm cannot edit` (the line text is the Name of the block, `<file>` its file). It applies in the main file, the managed file and other included files, and wins over the import hint (import cannot move such a line). |
| M2 | A single-pattern block of the typed name always wins over M1. Addressing the whole line text (`edit "db-1 db-2"`) returns the same error. After G3, M1 comes before not-found. |
| M3 | `Snapshot`: the entry of a multi-pattern line has `ReadOnlyReason` equal to the M1 text (both modes); P6 T2/T4 parity holds for it; `e`/`d`/`D` in the TUI show it as the toast. Hosts with a single pattern are unaffected. |

### Recovery
| ID | Clause |
|---|---|
| R1 | Interrupt safety. SIGINT, SIGTERM and SIGHUP received while a verified save is between its first write and the end of its verification (managed save, `setup`, `import` write steps) trigger the same rollback as a failed verification: the files are restored to their pre-write bytes, the lock is released, the process exits non-zero and prints `interrupted: <file> restored` on stderr. If the restore fails the message is `interrupted: could not restore <file>; backup: <path>`. Signals outside that window keep default behavior. SIGKILL is out of scope and documented (F5). Afterwards `ssh -G` works for all hosts that worked before. |
| R2 | The refusal `not writing <file>: the current ssh configuration is already broken: <ssh error>` (and the `setup` and `import` forms) appends `(newest backup of <file>: <path>)` when `sshm-backups/` holds a backup of that file; without a backup the text is unchanged. |

### Removal and docs
| ID | Clause |
|---|---|
| X1 | Deleted: `config.Write`, `writeDevPodBlock`, `writeDisabledBlock`, `DisabledBlockText`, `disabledBlockSpans`, `RawBlock` assignment, `ConfigFile.Comments`/`CommentBlock`/`flushComment` (only if nothing reads them), `App.load`/`App.save` rewrite paths, `ensureInMain`, `ensureGroupInMain`, `initLegacy`, `misplacedWildcardNote`, `SetupHint`, every `activeView() == nil` legacy branch of edit/forward/groups/init/cert/`CheckEdit`. Kept (see section 3): the helpers `Doc` needs, the read-side disabled-host code, `ensureInMainLoaded`, `activeView`/`viewOf`/`ManagedActive`, the legacy group-sidecar read gate. |
| X2 | Verification of X1: `go build`, `go vet`, `go test -race -count=1 ./...` green; `grep` finds no remaining reference to the deleted identifiers; no unreferenced non-test function is left behind by the removal (implementer reports the check used). |
| X3 | Layering unchanged: `internal/tui` and `internal/cli` import only `app` and `domain`; `domain` imports no internal package. |
| X4 | Existing tests that used legacy writes are migrated to managed (set-up) fixtures. Assertions may get stricter, never looser; tests that only exercised the removed writer (round trip, `config.Write`) are deleted. The report lists every changed or deleted test file with a reason. Frozen P3-P6 files are not edited, except the ones that cannot compile or whose subject is removed, each named in the report. |
| X5 | README and ARCHITECTURE: no legacy mode; first run is `sshm init` (fresh machine) or `sshm setup`; a limits list (multi-pattern `Host` lines, DevPod and `Match` blocks stay in the main file; clients that do not follow `Include` do not see managed hosts; a dotfile manager that overwrites the main file drops the Include; SIGKILL during a save). |

## 5. Non-goals
OpenSSH version check; override or hint when `setup` refuses a config ssh rejects; `restore` command; `validate` rule for an
ssh-rejected config (doctor D20); friendlier error for a missing config in read-only commands; TUI banner; locking redesign
(setup lock versus save lock); merging the duplicated save machinery of `setup`/`import` with `saveDocLocked`
(Fable refactoring review after P7); any change to doctor.

## 6. Open points for the skeleton/test round
- Skeleton: `*MultiPatternError`, the signal-aware save seam, the init-with-setup entry (signatures only).
- R1 is tested with a wrapper `ssh` that sleeps while the config contains a marker option, signal sent from a helper
  subprocess; the test agent decides the seam, the spec fixes only the outcome.
- Test files are named by topic (not-set-up gate, init-fresh, names, multi-pattern, interrupt), never by round.

## 7. Clarifications after the skeleton (binding)
Skeleton adds `*MultiPatternError{Host, File string; Line int}` and `(*App).InitFresh() (SetupResult, fresh bool, error)`
(`internal/app/setup.go`, stubs return `ErrNotImplemented`). The CLI `init` is not wired yet; the implementation round
calls `InitFresh` first and `InitDefaultsReport` only when `fresh` is false.
1. **I2 output.** Setup action lines and `note: ...` lines exactly as `sshm setup` prints them, on stderr; then one final
   stderr line: `created an empty <ManagedPath>; run 'sshm init' again to add the default Host * block`.
2. **Gate order (G3), uniform.** Inside the App every gated method checks the gate FIRST, before argument checks that
   exist today (`ValidateGroupName`, `checkHostArg`, CA key and public key lookup of `SignCert`). Only cobra-level
   flag and argument-count errors come before it.
3. **`SignCert` with a host:** gate before CA key lookup and before `ssh-keygen`. Without a host nothing is written to the
   config and there is no gate.
4. **`RevokeCert`:** `cert file not found` and inspection errors still come first (no config is touched). The gate fires
   when a referencing host is found (decided by today's code: CertificateFile or identity match), via
   `ClearCertificateFile`; the returned error may be wrapped (`cert file not deleted: ...: %w`), so tests assert
   `errors.Is(err, ErrNotSetUp)` and that the message contains the `ErrNotSetUp` text. Nothing is deleted.
5. **`ClearCertificateFile`:** gate first, also for an unknown host (no more silent nil).
6. **`InitDefaults` and `InitDefaultsReport`** are both gated.
7. **G4 scope:** gated methods and `CheckEdit` return `ErrNotSetUp` for a missing main file. `CheckHostName`, `CheckNewHost`
   and all read-only methods keep `read config: open ...`.
8. **`InitFresh`:** `fresh` is true whenever the main file was missing and the setup actions ran, also when
   `config.d/sshm.conf` already existed. A zero-byte or comment-only main file is NOT fresh: `init` returns `ErrNotSetUp` for it.
9. **Second `init` output** is unchanged (including the existing `Host *` note).
10. **M1/M2 precedence for one name:** single-pattern blocks are looked at first (in the managed file: normal edit; only
    elsewhere: `*UnmanagedHostError` wins). `*MultiPatternError` is returned only when no single-pattern block has that name.
11. **`MultiPatternError.File`** is the `SourceFile` the host carries, the same string `UnmanagedHostError.File` uses.
12. **G5:** the `printHint(a)` calls in the CLI (add, edit, forward x2, cert sign, groups disable/enable, init) and the
    function itself are removed with `SetupHint`.
