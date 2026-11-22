# P6: TUI editor on the managed file (spec, draft 1)

Phase P6 of `PLAN-include.md`. Branch `feat/tui-editor`, stacked on `feat/setup-import` (PR #5; P3 provides the
managed routing this phase builds on). Independent of the doctor PR (#7).
Decisions below were taken by Hermes from the P6 text of `PLAN-include.md` ("show source file per host; unmanaged
hosts read-only with the import hint; every TUI save goes through the managed save"); Adam reviews them in the PR.

## 1. Scope
Re-enable `e` (edit), `n` (new), `d` (duplicate), `D` (delete) in the TUI, but only in **managed mode**
(`App.ManagedActive()`), so no TUI write can reach the lossy legacy writer. Hosts that sshm does not own are shown
read-only with the reason. `Snapshot`, `CheckEdit` and the read-only decision become managed-aware.
Out of scope: Group field and rename in the editor, port validation, running `setup`/`import`/`doctor` from the
TUI, any change to the CLI commands.

## 2. Facts (current code)
- `Model.editable` (internal/tui/model.go) is off in `Run`; tests flip it on over a *legacy* fixture.
- `HostEntry.Included` = host defined only in files other than the main file. In managed mode the hosts of the
  managed file are therefore `Included == true` although sshm may edit them.
- `app.guardWrite` / `managedView.unmanaged` (internal/app/routing.go) decide ownership for writes and return
  `*UnmanagedHostError`; the TUI must show the same reasons.
- `CheckEdit` still uses the legacy `a.load()` and `ensureInMain`.

## 3. API (internal/app/snapshot.go)
```go
type HostEntry struct {
    domain.Host
    Gated    bool
    Included bool   // unchanged: defined only in files other than the main file
    // ReadOnlyReason is "" when the location allows edit, duplicate and delete
    // (managed mode: the host is defined in the managed file; legacy mode: it
    // is defined in the main file). Otherwise it is the refusal message the
    // write would return (the *UnmanagedHostError text, or the legacy
    // "included" refusal text). Gated and DevPod hosts are NOT reflected here.
    ReadOnlyReason string
}
type Snapshot struct {
    Hosts       []HostEntry
    Issues      []domain.Issue
    Managed     bool   // App.ManagedActive()
    ManagedPath string // App.ManagedPath()
}
```

## 4. Clauses

### App layer
| ID | Clause |
|---|---|
| T1 | `Snapshot.Managed` equals `ManagedActive()`; `ManagedPath` equals `ManagedPath()`. |
| T2 | Managed mode: `ReadOnlyReason == ""` exactly for hosts defined in the managed file. A host defined only in the main file has the text of `UnmanagedHostError{CanImport:true}` (`host "x" is defined in <main>, which sshm does not manage; run 'sshm import'`); one defined only in another included file has the `CanImport:false` text. |
| T3 | Legacy mode: `ReadOnlyReason == ""` for main-file hosts; an included-only host carries the legacy include refusal text of `EditHost`. |
| T4 | Parity: for every non-gated, non-DevPod host, `ReadOnlyReason == ""` iff `EditHost(name, <change equal to the current value>)` does not return an ownership refusal; when it is not empty it equals that error's message. |
| T5 | `CheckEdit(name, changes)` in managed mode: for a managed-file host returns the same issues `domain.Validate` yields for that host after applying the changes (as in legacy mode); for a host outside the managed file returns the `*UnmanagedHostError` `EditHost` returns; unknown host -> not-found error. It writes nothing. Legacy mode behaves as before. |
| T6 | `CheckHostName` / `CheckNewHost` treat a name defined in ANY loaded file (main, managed, other included) as existing. Nothing is written. |

### TUI
| ID | Clause |
|---|---|
| T7 | The `editable` field is removed. Editing is available iff the last loaded snapshot has `Managed == true`; `reload` (key `r` and after every save) re-evaluates it, so running `sshm setup` in another terminal and pressing `r` enables editing. |
| T8 | Legacy mode: `e`/`n`/`d`/`D` do not leave list mode, write nothing and show the error toast `editing needs setup: run 'sshm setup' to create <ManagedPath>`. The hints line omits the edit keys; the help overlay omits the edit key lines and contains the sentence `Editing is available after 'sshm setup'.`. |
| T9 | Managed mode: hints and help list the edit keys (as they did with `editable`). |
| T10 | Managed mode, `e`/`d`/`D` on a host with `ReadOnlyReason != ""`: error toast with the reason verbatim, mode stays list, nothing written. `n` still opens the new-host form. Gated and DevPod toasts are unchanged and take precedence as today. |
| T11 | Tags: a row whose host has `ReadOnlyReason != ""` shows `[included]` when `Included`, otherwise `[main]` (managed mode only). Hosts of the managed file show neither tag. Legacy mode keeps today's `[included]` tag and never shows `[main]`. The help overlay explains `[main]`/`[included]`. |
| T12 | Managed mode, saving the edit form changes only the managed file: the main file's bytes are unchanged; comments and other option lines of the edited block survive; `ssh -F <main> -G <host>` shows the new value. |
| T13 | Managed mode: `n` + save appends the host to the managed file; `d` (duplicate) creates the copy in the managed file; `D` + `y` removes the block from the managed file; in all three the main file's bytes are unchanged. |
| T14 | Save failure (the app returns an error, e.g. ssh rejects the value and the write is rolled back): the form stays open with the error text, the managed file is unchanged. Skip with a note when the form's own validation cannot be bypassed to reach it. |
| T15 | The editor's live validation (`CheckEdit`/`CheckNewHost`) works for managed-file hosts and for new names that exist only in the main file (duplicate error). |
| T16 | `internal/tui` imports only `app` and `domain` (layering unchanged). |

## 4.1 Clarifications after the test round (binding)
- **Name defined in both the main and the managed file:** ownership is decided per NAME exactly as `EditHost` decides it (T4 wins over the T2 wording): every entry of that name has `ReadOnlyReason == ""` because the managed definition exists. Tests do not cover this case.
- **Pattern blocks** (`Host web-*`, multi-pattern) are not listed by the TUI (`visibleHosts` drops wildcard blocks), so `e` on them is unreachable; no change.
- **Legacy mode precedence (T8):** the setup toast comes before any host-specific toast, also on a group header. In managed mode the gated/DevPod toasts take precedence over the ownership reason (T10).
- **Failed reload (T7):** keeps the last snapshot, editing stays as it was.
- **Legacy help (T11):** need not explain `[included]` more than today; it must never mention `[main]`.
- **`CheckEdit` issue `Line`/`File`** are those `domain.Validate` gives for the loaded managed host.
- The port field has no validation in the form (`Port notaport` reaches the app and is rolled back by the ssh verify step, T14).

## 4.2 Follow-up clauses (review round, 2026-11-16)
| ID | Clause |
|---|---|
| T17 | **Toast wrapping.** A toast longer than the terminal width wraps onto extra lines (at most 3, each at most the terminal width) instead of being clipped; the whole text stays visible in `View().Content` (e.g. the `run 'sshm import'` tail of a 95-character refusal at width 80). The view still has at most `height` lines in every mode. Short toasts occupy one line as before. |
| T18 | **Managed file that cannot be loaded.** `Snapshot.ManagedProblem string` (new field) is non-empty exactly when a loaded file has an UNCONDITIONAL `Include` that reaches the managed path, the managed file exists, and it could not be loaded (unreadable or unparsable): the text names the managed path and the load warning. In that state `Managed` is false, the TUI edit keys (`e`/`n`/`d`/`D`) show the error toast `editing disabled: <ManagedProblem>` instead of the "needs setup" text, and the write routing is unchanged. A missing managed file (never created) and the plain no-Include case leave `ManagedProblem` empty and keep the T8 toast. |

## 5. Test notes
- TUI tests build their fixture with a helper that writes a temp main config with an absolute
  `Include <tmp>/config.d/sshm.conf` as first line, a managed file holding the editable hosts, and main-file
  hosts for the read-only cases. Never touch the real `~/.ssh`; placeholders only.
- Real `ssh -F <main> -G` is the oracle for T12/T13.
- Existing tests that set `m.editable = true` over a legacy fixture must be moved to the managed fixture
  without weakening assertions (implementation round); the test agent writes NEW tests only.
