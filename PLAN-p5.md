# P5: `sshm doctor` (spec, draft 1)

Phase P5 of `PLAN-include.md`. Branch `feat/doctor` (stacked on `feat/setup-import`, PR #5).
Decision (Adam, 2026-11-15): port the rules of `origin/feat/linter` (commit `0e4c86a`, stale,
single-valued `IdentityFile`) into the new command; do not merge that branch.

## 1. Scope
`sshm doctor [--strict] [--skip-files]` is **report-only**. It runs every `validate` rule plus the
checks below, prints one line per finding, exits 1 on errors (or on warnings with `--strict`).
`validate` itself is unchanged (pure config rules, no filesystem and no ssh).
Out of scope for this phase: `--diff` / `--fix` (section 6, decision 1), changing `validate`,
TUI (P6).

## 2. Facts verified against OpenSSH 10.6 (temp dirs, never the real ~/.ssh)
- `ssh -F <main> -G <name>` with an `Include`d file that is group-writable (mode 664) fails with
  `Bad owner or permissions on <file>`. The same group-writable file used as `-F` main file is
  accepted, but ssh_config(5) requires "not writable by others" for the user config, so doctor
  flags group/other-writable on every config file it read.
- `ssh -G <name>` **executes** `Match exec` commands (verified: a marker file was created). Doctor
  must therefore never run ssh when a loaded file contains a `Match` with `exec`.
- ssh expands `~` with the passwd home and ignores `$HOME`.
- A private key readable by group/other is refused by ssh (`UNPROTECTED PRIVATE KEY FILE`).

## 3. API
```go
// internal/app/doctor.go
type DoctorOptions struct{ SkipFiles bool }
// Doctor returns validate's issues plus the doctor-only findings. It never
// writes anything and never creates a file or a backup.
func (a *App) Doctor(opts DoctorOptions) ([]domain.Issue, error)
```
`domain.Issue` is reused (`HostName`, `Severity`, `Rule`, `Message`, `Line`, `File`). New rules need
no new fields. CLI: `internal/cli/doctor.go`, flags `--strict`, `--skip-files`.

## 4. Clauses

### Output and exit status
| ID | Clause |
|---|---|
| D1 | Doctor never modifies anything: all config files, the managed file, the sidecar and the directories keep their bytes and mtimes; no file appears in `sshm-backups/`. |
| D2 | Every issue `Validate()` returns is part of the doctor result, unchanged (same rule, severity, message, line, file). |
| D3 | Output format is validate's: `<severity> [<rule>] <host>: <message> (<location>)` per issue on stderr. When there are no issues: `No issues found.` on stdout, exit 0. Otherwise a final stderr line `<E> error(s), <W> warning(s) found.` (info findings are not counted). |
| D4 | Exit status: the command returns a non-nil error (exit code 1) when `E > 0`, or when `--strict` and `W > 0`. Info never fails. With errors or warnings but no failure condition the command returns nil. |
| D5 | Ordering is deterministic: `Validate()` issues first (their existing order), then doctor-only findings in the order of this table (file checks before include checks before ssh checks); within one clause by file evaluation order, then line. |
| D6 | A missing main config file behaves as `validate` does (same error), no extra findings. |

### File checks (skipped entirely by `--skip-files`)
| ID | Rule | Sev | Clause |
|---|---|---|---|
| D7 | `missing-identity-file` | error | For every host block (wildcard blocks included) and every `IdentityFile` value of it (all values, not only the first): the file does not exist. Message `IdentityFile <path as written> does not exist`; `Line` = block start, `File` = source file. Not checked: value `none`, a value containing `%` or `$`, a relative path (not starting with `/` or `~`). `~` expands with the passwd home. |
| D8 | `missing-cert-file` | warning | Same as D7 for every `CertificateFile` value. |
| D9 | `unsafe-permissions` | error | An existing private key (an `IdentityFile` value that passes the D7 filters and does not end in `.pub`) has any group/other permission bit (`mode & 077 != 0`). Message names the path as written, the octal mode and `chmod 600`. |
| D10 | `unsafe-permissions` | error | A config file doctor read (main file and every included file, managed file included) is group- or other-writable (`mode & 022 != 0`). Message names the file and the octal mode. |
| D11 | `managed-permissions` | warning | The managed file exists and is readable by group or other (`mode & 044 != 0`) while not tripping D10. Message suggests `chmod 600`. (sshm creates it 0600.) |
| D12 | `cert-expired` | warning | An existing `CertificateFile` (D7 filters) whose certificate has expired (uses the existing `InspectCert` + `domain.ValidateCertExpiry`). An unparsable certificate or a missing `ssh-keygen` produces no finding. |
| D13 | (dedup) | | One finding per (host block, path); the same path in two blocks is reported once per block. |

### Include / setup checks
| ID | Rule | Sev | Clause |
|---|---|---|---|
| D14 | `not-set-up` | info | The managed file is not reached by any `Include` (state none; this includes a fresh machine). Message `sshm-managed file is not included; run 'sshm setup'`. |
| D15 | `include-conditional` | warning | The managed file is reached only conditionally (state conditional): message names `<file> line <n>`. |
| D16 | `include-conditional` | warning | Any other `Include` line in a loaded file that ssh reads only conditionally (below a `Host`/`Match` that is not `Host *` / `Match all`). Message `Include <pattern> is read only for matching hosts`. The managed Include is covered by D15, not reported twice. |
| D17 | `home-mismatch` | warning | `$HOME` is set and differs from the passwd home (compared after cleaning and symlink resolution). Message says ssh ignores `$HOME` for `~`. |

### ssh checks
| ID | Rule | Sev | Clause |
|---|---|---|---|
| D18 | `ssh-missing` | info | `ssh` is not in `PATH`: one finding `ssh not found; ssh-based checks skipped`, D19 and D21 not run. |
| D19 | `verify-skipped` | info | Some loaded file contains a `Match` line with an `exec` argument (same predicate sshm uses to skip save verification). Message says sshm cannot verify saves and doctor did not run ssh. D20 and D21 are not run in that case (`ssh -G` would execute the command). |
| D20 | `ssh-rejects-config` | error | `ssh -F <main> -G sshm-doctor-probe` exits non-zero. Message is the first non-empty stderr line of ssh. When it fires, D21 is not run. |
| D21 | `hardening-hashknownhosts` | info | The probe's effective `hashknownhosts` is not `yes`. |
| D22 | `hardening-identitiesonly` | info | The probe's effective `identitiesonly` is not `yes`. |
| D23 | `agent-forwarding-default` | warning | The probe's effective `forwardagent` is `yes` (agent forwarding enabled for every host). |

D21-D23 describe what an otherwise unmatched host gets, i.e. what `Host *` supplies. The probe
name must not collide with a real host; doctor uses `sshm-doctor-probe`.

### Flags
| ID | Clause |
|---|---|
| D24 | `--skip-files` omits exactly D7-D13. Everything else still runs. |
| D25 | `--strict` changes only the exit status (D4); output is identical with and without it. |

## 5. Test notes for the test agent
- Real `ssh -F <main> -G` is the oracle for D19/D20/D21-D23 expectations (compute the expected
  `hashknownhosts` etc. from ssh, not from the config text).
- `Match exec` fixture: use a command that creates a marker file in the temp dir; assert the
  marker does NOT exist after `Doctor` (D19 must not run ssh).
- D9/D10/D11 need `os.Chmod` on temp files; D17 needs `config.SetHomeDirForTest(tmp)` and
  `t.Setenv("HOME", other)`. Tests never touch the real `~/.ssh` (guard test applies).
- `ssh` absent (D18): run the test with `PATH` set to a dir without ssh.
- Placeholders only (example.com, 10.0.0.x).

## 6. Decisions (Adam, 2026-11-15)
1. `--diff` / `--fix`: not in this phase. Decide on fixes after reading real doctor findings.
2. Linter severities kept: `missing-identity-file` and `unsafe-permissions` are errors.
3. Hardening rules D21-D23 are included.
