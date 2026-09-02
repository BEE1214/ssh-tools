# SSH Tools — Plan

## Problem

- `~/.ssh/config` is 681 lines, ~50+ hosts, no structure.
- Inconsistent: `User`/`user`, `HostName`/`Hostname`, tabs vs spaces, leading-space `Host`, duplicate keys within blocks.
- No active `Host *` defaults — security/keepalive settings are commented out.
- Many hosts missing IdentityFile, several with `StrictHostKeyChecking no`.
- DevPod auto-generates blocks that shouldn't be hand-edited.
- No way to quickly search, group, or connect from CLI without remembering host names.

## Language: Go

Why Go over Python/Rust for this tool:

- **Single static binary.** No interpreter, no venv, no pip. You ssh into machines, not Python runtimes.
- **Fast startup.** A CLI/TUI tool should open instantly. Go binary: ~2ms. Python: 100-300ms.
- **BubbleTea** (TUI framework) is one of the best in any language — Elm architecture, clean state model, excellent test coverage. Ratatui (Rust) is comparable but Go is simpler to write.
- **Cobra** (CLI framework) is industry standard, handles subcommands, completion, help generation.
- **You already know Go.** Listed in your languages. No learning curve tax.
- **Cross-compile.** One binary works on emil, oliver, jefry (all Linux amd64/arm64).

Rust was considered — same single-binary benefit, but you don't list it and the learning curve isn't worth it for a utility tool. Python was considered — you know it well, but runtime dependency management for a tool you want everywhere is the wrong tradeoff.

## Libraries

| Purpose | Library | Why |
|---|---|---|
| CLI framework | `github.com/spf13/cobra` | Subcommands, shell completion, help. Standard. |
| TUI framework | `github.com/charmbracelet/bubbletea` | Elm-architecture TUI. Best-in-class. |
| TUI components | `github.com/charmbracelet/bubbles` | List, text input, viewport, spinner — prebuilt. |
| TUI styling | `github.com/charmbracelet/lipgloss` | Layout, colors, borders. Declarative. |
| Fuzzy filter | `github.com/sahilm/fuzzy` | Fuzzy matching for host search in TUI and CLI. |
| Config parsing | Custom parser | SSH config format is simple enough (key-value pairs under Host blocks). Existing Go libs (e.g. `kevinburke/ssh_config`) exist but have quirks with comments, formatting, and round-tripping. A custom parser preserves your existing formatting and comments. |
| Logging | `log/slog` (stdlib) | Structured logging, no dep. |

## Architecture

```
ssh-tools/
  cmd/
    sshm/
      main.go          # entry point, cobra root
  internal/
    config/
      parser.go        # parse ~/.ssh/config -> []Host
      writer.go        # write []Host -> ~/.ssh/config (preserve comments, formatting)
      validate.go      # lint: missing IdentityFile, dup keys, weak settings
      defaults.go      # Host * block generation, security presets
    tui/
      model.go         # bubbletea Model (state)
      views/
        list.go        # host list with filter
        edit.go        # edit single host
        group.go       # group/ungroup hosts
    cli/
      list.go          # sshm list
      connect.go       # sshm connect <host> (exec ssh)
      add.go           # sshm add
      edit.go          # sshm edit <host>
      search.go        # sshm search
      validate.go      # sshm validate
      dump.go          # sshm dump <host> (effective config, like ssh -G)
      groups.go        # sshm groups
    host/
      host.go          # Host struct: Name, HostName, User, Port, IdentityFile, ProxyJump, ...
      group.go         # grouping logic (by prefix/tag)
  go.mod
  go.sum
```

## CLI Design

Binary name: `sshm` (SSH Manager).

```
sshm                         # no args -> launch TUI
sshm list                    # list all hosts, grouped
sshm list --flat             # flat list, one per line (for scripting/fzf)
sshm list --group host      # filter by group
sshm <hostname>              # connect: exec ssh <hostname> (replaces process)
sshm connect <hostname>      # same as above, explicit
sshm search <pattern>         # fuzzy search host names + hostnames
sshm add                     # interactive prompt or flags: --name --hostname --user --port --identity
sshm edit <hostname>         # open host in TUI editor view
sshm dump <hostname>         # show effective config (what ssh -G shows)
sshm validate                # lint config, report issues
sshm groups                  # list detected groups + host counts
sshm init                    # generate/repair Host * defaults block
```

### Integration with existing workflow

- `sshm <host>` uses `syscall.Exec` to replace itself with `ssh <host>` — no wrapper overhead, ssh behaves exactly as if you typed it.
- `sshm list --flat | fzf | xargs sshm` — works with fzf for quick selection.
- Shell completion via cobra: `source <(sshm completion bash)`.
- Does NOT replace `ssh` — it's a separate binary. Your muscle memory (`ssh <host>`) keeps working.
- DevPod blocks detected by marker comments (`# DevPod Start/End`) — marked read-only in TUI, never reformatted.

## TUI Design

### Main view: Host list
```
┌─ SSH Manager ──────────────────────────────────────────────────────┐
│ Filter: host                                           [42 hosts]   │
│                                                                    │
│ ▸ host           (6 hosts)                                        │
│   ▾ host-acq-dev      root @ example.com:20008  no key  │
│   ▾ host-acq-local    root @ 10.0.0.5:20008              no key  │
│   ▾ host-dev-acq      root @ 10.0.0.6:20008                   │
│   ▸ host-dev-plc      root @ 10.0.0.6:20010                   │
│   ▸ host-plc-dev      root @ example.com:20010   no key  │
│   ▸ host-router       adam @ 10.0.0.4:22              id_ed25519 │
│                                                                    │
│ ▸ zf-poland     (7 hosts)                                         │
│ ▸ karel        (5 hosts)                                         │
│ ▸ gpu-cluster  (4 hosts)                                         │
│ ▸ ungrouped    (12 hosts)                                        │
│ ───────────────────────────────────────────────────────────────── │
│ ↑↓ navigate  → expand  e edit  n new  d duplicate  D delete  ? help │
└────────────────────────────────────────────────────────────────────┘
```

### Edit view: Single host
```
┌─ Edit: host-acq-dev ──────────────────────────────────────────────┐
│                                                                    │
│ Host:       [host-acq-dev                                      ]  │
│ HostName:   [example.com                              ]  │
│ User:       [root                                              ]  │
│ Port:       [20008                                             ]  │
│ IdentityFile:[~/.ssh/id_ed25519                            ]  │
│ ProxyJump:  [                                                  ]  │
│ Group:      [host                                            ]  │
│                                                                    │
│ ⚠ No IdentityFile set                                              │
│ ⚠ StrictHostKeyChecking no — consider accept-new                  │
│                                                                    │
│ Tab next field  Enter save  Esc cancel                             │
└────────────────────────────────────────────────────────────────────┘
```

### Grouping logic

Auto-detect groups by common prefix before first `-`:
- `host-*` -> group `host`
- `zf-poland*` -> group `zf-poland`
- `karel-*` -> group `karel`
- `gpu-cluster-*` -> group `gpu-cluster`

Manual override via `# group: <name>` comment in config. Hosts without a detectable group go to `ungrouped`.

## Security improvements (built into `sshm init`)

`sshm init` generates or repairs a `Host *` block at the top of config:

```
Host *
    # Connection keepalive
    ServerAliveInterval 60
    ServerAliveCountMax 3

    # Security
    IdentitiesOnly yes
    HashKnownHosts yes
    StrictHostKeyChecking accept-new

    # Post-quantum + modern KEX
    KexAlgorithms mlkem768x25519-sha256@openssh.com,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org

    # Strong host key algorithms
    HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

    # Strong ciphers and MACs
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
```

`sshm validate` checks:
- Missing IdentityFile (warn)
- `StrictHostKeyChecking no` (warn — suggest `accept-new`)
- Duplicate keys within a block (error)
- Duplicate host names (error)
- Mixed case keys (info — normalize)
- Missing User (warn)

## Config round-trip preservation

The parser preserves:
- Comments (standalone and inline)
- Blank lines
- DevPod blocks (marker-based, never reformatted)
- Original ordering

Writer only touches blocks that were edited in TUI. Everything else is byte-for-byte preserved. This is why a custom parser is preferred over existing libraries — round-trip fidelity matters when the file is also managed by DevPod and hand-edited.

## Implementation phases

### Phase 1: Config parser + writer + CLI skeleton
- Parse `~/.ssh/config` into `[]Host`
- Write back with formatting preservation
- `sshm list`, `sshm list --flat`, `sshm validate`, `sshm dump`
- Cobra root + completion

### Phase 2: TUI — list + edit
- BubbleTea model, host list with fuzzy filter
- Group expansion/collapse
- Edit form for single host
- Add/duplicate/delete

### Phase 3: Connect + integration
- `sshm <host>` exec
- `sshm init` (Host * defaults)
- `sshm search`
- fzf integration docs
- Shell completion

### Phase 4: Polish
- Validate-on-save in TUI
- Config diff preview before write
- Backup `~/.ssh/config.bak` before write
- `sshm groups` view

## Not in scope

- SSH key generation/management (use `ssh-keygen`)
- Known hosts management (separate file, separate concern)
- SSH agent interaction
- Multiplexing/tmux integration
- Remote command execution beyond `ssh <host>`
- Windows support (you're all Linux)