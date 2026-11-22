# SSH Tools — Architecture

## High-level overview

```
┌──────────────────────────────────────────────────────┐
│                    User                               │
│              (keyboard / terminal)                    │
└──────────┬──────────────────────────┬───────────────┘
           │                          │
     ┌─────▼──────┐           ┌──────▼───────┐
     │    TUI     │           │     CLI      │
     │ (bubbletea)│           │   (cobra)    │
     └─────┬──────┘           └──────┬───────┘
           │                          │
           └──────────┬───────────────┘
                      │
              ┌───────▼────────┐
              │   App layer    │   orchestration, command handlers
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │  Domain layer   │   Host, Group, Validation
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │  Config layer   │   parse / line editor / backup
              └───────┬────────┘
                      │
              ┌───────▼────────────────────────────┐
              │  ~/.ssh/config  +  config.d/sshm.conf │   sshm writes only the second
              └────────────────────────────────────┘
```

Three layers, strict dependency direction downward:

1. **Config layer** — file I/O, parsing, editing lines of a file. Knows about SSH config syntax. Knows nothing about TUI or CLI.
2. **Domain layer** — Host struct, Group logic, validation rules, effective-config resolution. Pure Go, no I/O.
3. **App layer** — wires CLI/TUI commands to domain+config. Handles backup, atomic writes, exec.

The TUI and CLI are thin presentation layers. They construct requests, call the app layer, render results. No business logic in either.

## Core data model

```
// Host is a single Host block in ssh config.
type Host struct {
    Name         string            // what a user types: the one pattern of the Host line ("web-1" for
                                   // `Host web-1 # prod`), several patterns joined by one space
                                   // ("db-1 db-2"), can be a wildcard
    HostName     string            // resolved hostname/IP
    User         string
    Port         string            // keep as string, "22" default
    IdentityFile string
    ProxyJump    string
    ProxyCommand string
    ForwardAgent bool
    ForwardX11   bool
    StrictHostKeyChecking string   // "", "yes", "no", "accept-new"
    LogLevel     string
    HostKeyAlgorithms string
    KexAlgorithms string
    // unknown / less common options
    Extra        map[string]string // anything not explicitly modeled

    // metadata (not written to config, derived)
    Group        string            // derived from Name prefix or # group: comment
    Source       HostSource        // manual | devpod
    LineStart    int               // 1-indexed line in original file
    LineEnd      int
}

// ConfigFile is the parsed representation of one file. It is read-only: sshm
// never writes a file back from it (edits go through config.Doc, below).
type ConfigFile struct {
    Hosts    []Host
    Raw      []byte               // original file bytes
    Includes []IncludeDirective
}
```

Why `Extra map[string]string` instead of modeling every possible SSH option:
- SSH has 100+ options. Modeling all is busywork with no payoff.
- Options you actually use (HostName, User, Port, IdentityFile, ProxyJump, ProxyCommand, ForwardAgent, ForwardX11, StrictHostKeyChecking, LogLevel, HostKeyAlgorithms, KexAlgorithms) are first-class fields.
- Everything else goes in Extra. A new block is written with them verbatim and edits of a block leave lines they do not touch alone. This means any option works, even ones we've never seen.

Why `Port` is string not int:
- Default is "22" (string in ssh config). Avoids int->string conversion noise.
- Unknown/non-numeric ports don't exist in practice but string is simpler.

Why `Source` field:
- DevPod blocks are delimited by `# DevPod Start <name>` / `# DevPod End <name>` comments. The parser sets `Source: SourceDevPod` for these. TUI shows them as read-only. They stay in the main file, where sshm never edits them.

## Module breakdown

### internal/config — File I/O and SSH config format

```
config/
  parser.go      Parse(raw []byte) (*ConfigFile, error)   // read-only view of one file
  load.go        Load(main string) (*Loaded, error)       // main file + everything it Includes
  doc.go         Doc: line-based editor of the managed file (SetOption, AppendBlock, DisableBlocks, ...)
  doc_raw.go     BlockLines, AppendRaw, RemoveSpans: raw line edits (init's Host *, import)
  writer.go      the canonical text of one new host block (used by Doc.AppendBlock and BlockLines)
  backup.go      BackupTo(path, dir) (string, error)      // timestamped copy in sshm-backups/
  atomic.go      AtomicWrite(path string, data []byte) error
  locate.go      FindConfig() (string, error) // $SSH_AUTH_CONFIG or ~/.ssh/config
```

**Parser design:**

Line-by-line state machine. Three states:

```
IDLE ──────"Host X"──────► IN_HOST
  │                          │
  │                       key-value
  │                          │
  │◄────blank/comment────────┘
```

- `IDLE`: skip comments and blank lines.
- `IN_HOST`: accumulate key-value pairs into current Host.
- Comments inside a host block (between key-value lines) are skipped; they stay in the file.
- `Host *` (wildcard) is parsed as a normal Host with `Name: "*"`. It is not special-cased when resolving effective config: like every block it applies in file order, and since ssh is first-wins it only supplies true defaults when placed *after* the specific blocks. (`sshm init` therefore appends a new `Host *` as the last host block of the main file; an existing one is never rewritten and `init` prints a note saying where it is.)

`sshm validate` flags mixed-case option names as info. sshm does not normalize the casing or formatting of existing lines.

**Editing design (no re-serialization):**

sshm never builds a file from parsed hosts. Every write is an edit of lines of ONE file, the managed file `config.d/sshm.conf` that the main file includes (one `Include` line, set up by `sshm setup`, or by `sshm init` on a machine without an ssh config). `config.Doc` holds the file as its lines and changes only what an operation names: set or unset an option line, append a new block (canonical format, 2-space indent, `HostName` not `Hostname`), delete or duplicate one block, comment a group's blocks out between markers. Everything else is byte-for-byte what was read. The main file is only ever touched by the Include line `setup` inserts, the `Host *` block `init` appends, and the blocks `import` removes.

Every command that writes an ssh config first checks that the config is set up (`ErrNotSetUp` otherwise, before any argument check and without touching a file). A host that is not defined in the managed file (the main file, an included file) or whose `Host` line has several patterns is refused with a message saying why.

**Save pipeline** (`saveManagedDoc`, also used for `init` and, in its own form, `setup` and `import`): lock, check that the file is still what the edit started from, ask `ssh -G` for every host (and the sentinel name) before, back up the file into `sshm-backups/`, write atomically, ask `ssh -G` again and compare under the edit's plan, restore the old bytes if anything differs or ssh fails. SIGINT, SIGTERM and SIGHUP are handled only between the first write and the end of this verification: the same restore runs and the command exits with `interrupted: <file> restored`. A process killed with SIGKILL in that window leaves the file as written; the next save refuses ("already broken") and names the newest backup.

**Atomic write:**
- Write to temp file in same directory (`~/.ssh/.config.tmp.XXXX`).
- `fsync` the temp file.
- `rename` temp over the file.
- This prevents corruption if the process is killed mid-write.

### internal/domain — Pure logic, no I/O

```
domain/
  host.go       Host struct, methods
  group.go      GroupFor(name string) string, GroupHosts(hosts []Host) map[string][]Host
  validate.go   Validate(hosts []Host) []Issue
  resolve.go    EffectiveConfig(hosts []Host, hostName string) (Host, error)
```

**GroupFor logic:**

```
func GroupFor(name string) string {
    // explicit: "host-acq-dev" with group comment -> "host"
    // auto: split on first "-"
    // "zf-poland3-mgmt" -> "zf-poland" (first two segments if second is non-numeric)
    // "emil" -> "" (no dash, ungrouped)
    // "gpu-cluster-node-white" -> "gpu-cluster"
}
```

Rule: prefix up to first dash, but if the segment after the dash is numeric, include it (so `zf-poland3` -> `zf-poland`, not `zf`). Implementation:

```
parts = split(name, "-")
if len(parts) == 1:
    return ""              // ungrouped
if isNumeric(parts[1]):
    return parts[0]        // "gpu" from "gpu-cluster-..." — wrong
```

Better approach — group by the longest non-numeric prefix:

```
func GroupFor(name string) string {
    parts := strings.Split(name, "-")
    if len(parts) <= 1 {
        return ""
    }
    // take parts while next part is non-numeric
    group := parts[0]
    for i := 1; i < len(parts); i++ {
        if isNumeric(parts[i]) {
            break
        }
        group += "-" + parts[i]
    }
    return group
}
```

Test cases:
- `host-acq-dev` -> `host`
- `zf-poland3-mgmt` -> `zf-poland`
- `zf-poland1-svs` -> `zf-poland`
- `gpu-cluster-node-white` -> `gpu-cluster-node`
- `karel-pve-proxy` -> `karel-pve`
- `emil` -> `` (ungrouped)
- `cooper2-local` -> `cooper`

This matches your naming convention well. Manual override via `# group: <name>` comment above the Host line takes precedence.

**EffectiveConfig resolution:**

Mirrors what `ssh -G <host>` does:
1. Walk all Host blocks in ssh evaluation order (file order, `Include`d files inlined at the `Include` line).
2. A block applies if its pattern line matches the host name: `*` and `?` globs, space-separated alternatives, and `!pattern` negation (at least one positive pattern must match and no negated one may).
3. **First match wins** for scalar options (User, Port, HostName, ...): a later block only fills options that are still unset. So a `Host *` block placed *before* a specific block overrides it, exactly as in ssh.
4. List options accumulate across matching blocks, de-duplicated: `LocalForward`, `RemoteForward`, `DynamicForward`, `SendEnv`.
5. Return the merged Host.

Known limitation: `IdentityFile` / `CertificateFile` are single-valued in the Host model (ssh accumulates them), so they are first-wins here. `Match` blocks are not modeled.

This is used by `sshm dump <host>`. It's also used by the TUI edit view to show the effective config for a host that inherits from `Host *`.

**Validate rules:**

```
type Issue struct {
    HostName string
    Severity Severity    // error | warning | info
    Rule     string       // "missing-identity", "strict-no", "dup-key", ...
    Message  string
    Line     int
}

Rules:
  error   duplicate-host     Two Host blocks with same Name
  error   dup-key            Same key appears twice in one block
  warning missing-identity   No IdentityFile (will use ssh-agent or default key)
  warning strict-no          StrictHostKeyChecking no
  warning no-port            No port specified and not 22 (implicit, but worth showing)
  info    mixed-case         Key uses non-canonical casing (user vs User)
  info    leading-space      Host line has leading whitespace (valid but unusual)
```

### internal/app — Orchestration

```
app/
  app.go        App struct, holds config path, provides methods
  list.go       ListHosts(filter) -> []Host
  search.go     SearchHosts(pattern) -> []Host (fuzzy)
  add.go        AddHost(host Host) -> error
  edit.go       EditHost(name string, changes map[string]string) -> error
  delete.go     DeleteHost(name string) -> error
  duplicate.go  DuplicateHost(srcName, newName string) -> error
  connect.go    Connect(name string) -> error    // exec ssh
  validate.go   Validate() -> []Issue
  init.go       InitDefaults() -> (note, error)  // append/repair Host * block (last; existing updated in place)
  dump.go       Dump(name string) -> (Host, error)
```

**App struct:**

```
type App struct {
    configPath string
}

func NewApp() (*App, error) {
    path, err := config.FindConfig()
    if err != nil {
        return nil, err
    }
    return &App{configPath: path}, nil
}
```

No state held between operations. Each method reads config fresh from disk, does its thing, writes if needed. This means:
- No stale cache problem — file is always read on every operation.
- No sync issues if you hand-edit the file while TUI is open. TUI reloads on focus (or on explicit refresh key).

The TUI holds an in-memory `Snapshot` for display, but on save it calls `app.EditHost()` which re-reads, edits the managed file's lines, verifies and returns. The TUI then reloads. On a config that is not set up the TUI's editing keys only show a notice (`app.CheckEdit` returns `ErrNotSetUp`).

### internal/cli — Cobra commands

```
cli/
  root.go       cobra.Command root, launches TUI if no subcommand
  list.go       sshm list [--flat] [--group <name>]
  connect.go    sshm <hostname> / sshm connect <hostname>
  search.go     sshm search <pattern>
  add.go        sshm add [--name ... --hostname ... --user ... --port ... --identity ...]
  edit.go       sshm edit <hostname>
  dump.go       sshm dump <hostname>
  validate.go   sshm validate
  groups.go     sshm groups
  init.go       sshm init
  completion.go cobra builtin
```

**Connect implementation:**

```
func runConnect(name string) error {
    // verify host exists in config
    hosts, _ := app.ListHosts("")
    if !find(hosts, name) {
        return fmt.Errorf("host %q not found", name)
    }
    // exec ssh — replace process
    binary, _ := exec.LookPath("ssh")
    argv := append([]string{"ssh"}, name)
    syscall.Exec(binary, argv, os.Environ())
    return nil  // never reached
}
```

`syscall.Exec` replaces the process. No child process, no wrapper overhead, no signal forwarding issues. ssh gets direct control of stdin/stdout/stderr/tty. This is the same mechanism `sudo` and `exec` use.

**Root command behavior:**

```
rootCmd := &cobra.Command{
    Use: "sshm",
    Run: func(cmd *cobra.Command, args []string) {
        if len(args) == 1 && isHostName(args[0]) {
            runConnect(args[0])     // sshm host-acq-dev
        } else {
            runTUI()                // sshm (no args)
        }
    },
}
```

`sshm <host>` connects. `sshm` with no args launches TUI. Subcommands (`sshm list`, etc.) take precedence via cobra's dispatch.

### internal/tui — BubbleTea

```
tui/
  model.go        top-level Model, holds App + ConfigFile + current view
  update.go      message handling, key dispatch
  view.go        renders current view
  messages.go    custom messages (HostSaved, ValidationError, etc.)
  components/
    list.go      host list component (grouped, filterable)
    editor.go    host edit form component
    filterbar.go fuzzy filter input
    statusbar.go bottom status/help bar
```

**Model state:**

```
type Model struct {
    app       *app.App
    config    *config.ConfigFile   // in-memory for display
    view      View                  // ViewList | ViewEditor
    filter    string                // fuzzy filter text
    cursor    int                   // selected index in visible list
    expanded  map[string]bool       // which groups are expanded
    editor    *EditorModel          // nil unless ViewEditor
    width     int
    height    int
    err       error
    dirty     bool                  // config changed externally?
}
```

**Update loop (Elm architecture):**

```
Update(msg, model) -> (model, cmd)

Key messages:
  KeyMsg:
    "/"           -> enter filter mode
    ESC           -> exit filter / cancel editor
    Enter         -> connect to host (if list) or save (if editor)
    "e"           -> open editor for selected host
    "n"           -> new host editor (blank)
    "d"           -> duplicate selected
    "D"           -> delete selected (with confirm)
    "r"           -> reload config from disk
    Up/Down       -> move cursor
    Right/Left    -> expand/collapse group
    "?"           -> help overlay

  Custom messages:
    HostSavedMsg    -> reload config, show toast
    ValidationError -> show errors in editor
    ConfigReloaded  -> update in-memory config
```

**Component composition:**

The list and editor are separate BubbleTea components but share the parent Model. The parent delegates `Update` and `View` to the active component. This keeps each component focused and testable.

The editor form uses `bubbles/textinput` for each field. Tab/Shift-Tab cycles fields. Enter on the last field (or a Save button) triggers save.

## Data flow diagrams

### Read flow (list, search, dump, validate)

```
disk ~/.ssh/config
  │
  ▼
config.Parse(raw []byte)
  │
  ▼
*config.ConfigFile { Hosts: []Host, ... }   (config.Load: the main file plus its Includes)
  │
  ▼
domain.GroupHosts(hosts) → map[string][]Host   (for list/groups)
domain.Validate(hosts) → []Issue               (for validate)
domain.EffectiveConfig(hosts, name) → Host      (for dump)
  │
  ▼
CLI: print table / TUI: render
```

### Write flow (add, edit, delete, init)

```
User action (CLI flags or TUI form)
  │
  ▼
app.EditHost(name, changes)
  │
  ├─► gate: the main file includes the managed file, else ErrNotSetUp
  │
  ├─► config.Load(main)               // re-read fresh, with Includes
  │     └─► host must be a single-pattern block of the managed file
  │         (else *UnmanagedHostError / *MultiPatternError)
  │
  ├─► config.ParseDoc(managed file) → Doc.SetOption / AppendBlock / ...
  │     └─► only the lines the edit names change
  │
  └─► saveManagedDoc(managed, doc, plan)
        ├─► lock, ssh -G of every host before
        ├─► BackupTo(managed, <ssh dir>/sshm-backups)
        ├─► AtomicWrite: write temp → fsync → rename
        └─► ssh -G after, compare under plan; restore the old bytes on any
            difference, ssh error or SIGINT/SIGTERM/SIGHUP
```

### Connect flow

```
sshm host-acq-dev
  │
  ▼
app.ListHosts("") → find "host-acq-dev"
  │
  ├─► not found? → error: "host not found"
  │
  └─► found → syscall.Exec("ssh", "ssh", "host-acq-dev", env)
        └─► process replaced, ssh takes over
```

## Key design decisions

### 1. No external database or state file

`~/.ssh/config` is the database. The tool is stateless between invocations. Benefits:
- `ssh`, `scp`, `rsync`, git-over-ssh all read the same file — no sync needed.
- If you delete the tool, your config is intact and usable.
- No risk of desynchronized state.

### 2. Line edits of one managed file, never a re-serialization

Editing one host should not reformat anything else. sshm changes only the lines an operation names, in its own file `config.d/sshm.conf`, which the main file includes. This preserves:
- DevPod blocks and everything else in your own file (never touched)
- Your hand-written comments
- Your preferred ordering
- Inline comments you added

The one append to your own file is the `Host *` block of `sshm init`; `sshm setup` adds the one `Include` line and `sshm import` removes the blocks it moves.

Known limits: a `Host` line with several patterns cannot be edited; DevPod and `Match` blocks stay in the main file; clients that do not follow `Include` do not see the managed hosts; a dotfile manager that overwrites the main file drops the `Include` line (writes then fail with `ErrNotSetUp`); SIGKILL during a save can leave the file as written, the next save refuses and names the newest backup.

### 3. Domain layer is pure

`domain/` has no imports from `config/`, `app/`, `cli/`, or `tui/`. It takes `[]Host` and returns results. This makes it trivially testable with table-driven tests — no mocking filesystem, no temp files.

### 4. App layer re-reads on every operation

No in-memory cache in the app layer. Each method reads the file, does its work, writes if needed. The TUI holds an in-memory copy for rendering but always saves through the app layer (which re-reads first). This prevents lost updates if you edit the file in another terminal while the TUI is open.

### 5. `Extra` map for unknown options

SSH has 100+ config options. We model ~12 as first-class fields. The rest go in `Extra map[string]string`. A new block writes them verbatim. This means:
- Any SSH option works, even ones we've never seen.
- No need to update the tool when OpenSSH adds new options.
- TUI shows known fields in the edit form; Extra options shown in a "raw options" section.

### 6. Group detection is heuristic, overridable

Auto-detection by prefix is convenient but imperfect. `# group: <name>` comment above a Host line provides explicit override. The TUI shows detected groups and lets you reassign.

## Error handling

- **Parse errors**: non-fatal. Skip the problematic line, collect all errors, report them in `sshm validate` and in TUI status bar. Don't refuse to work — the file might have a typo but the user still needs to connect.
- **Write errors**: fatal for that operation. Backup is already created, temp file is cleaned up. Original file untouched (atomic write).
- **Host not found**: error message with suggestion (fuzzy match: "did you mean host-acq-dev?").
- **Validation on save**: errors block save, warnings show but don't block. User can override with a force flag in CLI or a confirm in TUI.

## Testing strategy

### Domain layer (pure, table-driven)

```
TestGroupFor:
  "host-acq-dev"   -> "host"
  "zf-poland3-mgmt" -> "zf-poland"
  "emil"            -> ""
  ...

TestValidate:
  host with no IdentityFile -> []Issue{warning}
  two hosts same name        -> []Issue{error}
  ...

TestEffectiveConfig:
  Host * + Host foo -> merged result
```

### Config layer (golden file tests)

```
testdata/
  basic.config
  basic_expected.config
  devpod.config
  mixed_case.config
  ...

TestParse:
  for each testdata file:
    parse -> compare hosts to expected

TestDoc (unit and property tests):
  edit a Doc -> bytes outside the edit unchanged, Doc and Parse agree on the hosts
```

### Integration tests

```
TestConnectExec:
  // can't actually exec ssh in tests, but verify:
  // - host lookup works
  // - error message for unknown host
  // - correct argv construction

TestFullWorkflow:
  create temp config -> add host -> edit host -> validate -> dump
  (end-to-end through app layer, temp file)
```

## Package dependency graph

```
cli ──► app ──► domain
 │       └──► config ──► domain
 │
tui ──► app
 │    ──► domain (for display types)
 │
 └──► (cobra, bubbletea, lipgloss, bubbles)
```

Rules:
- `domain` imports nothing internal.
- `config` imports `domain` (uses Host struct).
- `app` imports `domain` + `config`.
- `cli` and `tui` import `app` + `domain`.
- `cli` and `tui` do not import `config` directly — they go through `app`.

This keeps the dependency graph clean and makes swapping the presentation layer (e.g. adding a web UI later) possible without touching domain or config layers.