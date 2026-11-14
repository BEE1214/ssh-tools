# sshm — SSH Config Manager

TUI and CLI tool for managing `~/.ssh/config`. Reads and writes your SSH config directly — no database, no shadow state, no separate format.

> **Warning:** This project is AI-generated. The code, tests, and documentation
> were produced with the assistance of AI tools. Review before relying on it
> for anything important.

## Status

CLI and TUI (list, filter, edit, new, duplicate, delete) are working. The TUI has been tested through its model and in a pty smoke test; see [Known limitations](#known-limitations).

## Why

When your `~/.ssh/config` has 50+ hosts across multiple projects, sites, and DevPod environments, managing it by hand gets messy:

- Inconsistent casing (`User` vs `user`, `HostName` vs `Hostname`)
- Missing `IdentityFile` on many hosts
- `StrictHostKeyChecking no` scattered around
- Duplicate host names
- No `Host *` defaults block
- DevPod auto-generates blocks you shouldn't hand-edit
- No quick way to search or connect without remembering host names

`sshm` fixes this by working as a layer on top of `~/.ssh/config`.

## Install

```bash
./install.sh
```

Builds the project, installs the binary to `$HOME/.local/bin`, and optionally installs shell completion for bash/zsh/fish to `/usr/share/sshm/`.

Or build manually:

```bash
go build -o bin/sshm ./cmd/sshm/
```

Move `bin/sshm` somewhere in your PATH.

## Usage

```
sshm                         # launch TUI (needs a terminal; use 'sshm list' in scripts)
sshm <hostname>              # connect: exec ssh <hostname>
sshm connect <hostname>      # same, explicit
sshm list                    # list all hosts, grouped
sshm list --flat             # one host per line (for fzf)
sshm list --group mygroup    # filter by group
sshm search <pattern>        # search host names and hostnames
sshm add --name foo --hostname 10.0.0.1 --user root --port 22 --identity ~/.ssh/id_ed25519
sshm edit <hostname> --user root --port 20008
sshm dump <hostname>         # effective config (like ssh -G)
sshm validate                # lint config, report issues
sshm groups                  # list groups + enable/disable state
sshm groups disable <group>  # disable a group (hard gate, see below)
sshm groups enable <group>   # re-enable a disabled group
sshm init                    # generate/repair Host * defaults block
```

### Connect

`sshm <host>` replaces the current process with `ssh <host>` via `syscall.Exec`. Zero overhead — ssh gets direct control of stdin/stdout/stderr/tty.

### TUI

`sshm` with no arguments opens a grouped host browser. Groups start collapsed. Enter on a host quits the TUI (restoring the terminal) and then connects exactly like `sshm <host>`.

| Key | Action |
|-----|--------|
| `↑`/`k`, `↓`/`j` | Move cursor |
| `→`/`l`, `←`/`h` | Expand / collapse group (`←` on a host jumps to its group) |
| `Enter` | Connect to host; toggle a group |
| `/` | Fuzzy filter by host name (flat list of matches). `Enter` keeps the filter, `Esc` clears it |
| `r` | Reload config from disk |
| `?` | Help |
| `q`, `Esc`, `Ctrl+C` | Quit without connecting |

**Editing is currently disabled in the TUI.** The config writer re-serializes the whole file (see Known limitations), so `e`/`n`/`d`/`D` only show a notice; use the CLI (`sshm edit`, `add`, `copy`). The editor code is in place and returns once the managed-config writer from `PLAN-include.md` lands. When enabled: `e` edit, `n` new, `d` duplicate, `D` delete (asks `y`/`n`).

In the editor: `Tab`/`Shift+Tab` move between fields, `Enter` on the last field or `Ctrl+S` saves, `Esc` cancels. Validation errors block the save and are shown inline; warnings (e.g. no `IdentityFile`) are shown but do not block.

- Hosts in a disabled group are shown dimmed with a `[disabled]` tag and cannot be connected to, edited or deleted. Enable the group with `sshm groups enable <group>`.
- DevPod hosts are tagged `[read-only]`: you can connect to them, but not edit, duplicate or delete them.
- The host name is read-only when editing (there is no rename operation); to rename, duplicate and delete.
- The status bar shows the number of validation warnings/errors in the config (`sshm validate` lists them).
- All changes go through the same code path as the CLI: the file is re-read, a backup is written, and the new content is written atomically. The TUI never overwrites changes made to the file while it is open.

### fzf integration

```bash
sshm list --flat | fzf | xargs sshm
```

### Shell completion

```bash
source <(sshm completion bash)   # or zsh, fish
```

## Validation rules

| Severity | Rule | Description |
|----------|------|-------------|
| error | duplicate-host | Two Host blocks with same name |
| error | dup-key | Same key twice in one block |
| warning | missing-identity | No IdentityFile set |
| warning | strict-no | StrictHostKeyChecking no |
| info | mixed-case | Non-canonical key casing |

## Grouping

Hosts are auto-grouped by the first segment before a dash:

```
prod-web-01     -> prod
prod-db-02      -> prod
staging-api-01  -> staging
myhost          -> (ungrouped)
```

Override with a `# group: <name>` comment above the Host line (takes
precedence over the name prefix):

```
# group: prod
Host web-prod-1
  HostName 10.0.0.1
```

## Disabling groups

Use case: hosts you must not reach by accident (e.g. production deployments).
Disabling a group is a hard gate, not just an sshm-side guard:

```bash
sshm groups disable deploy     # comment the group's host blocks out
sshm groups                    # show groups + which hosts are disabled
sshm groups enable deploy      # restore the blocks byte-for-byte
```

What disable does:

- The group's host blocks are commented out of `~/.ssh/config` between
  `# sshm disabled group=<name> start/end` markers — raw `ssh <host>` no
  longer resolves them.
- The group is recorded in `~/.ssh/config.sshm-groups` (sidecar state).
- `sshm connect <host>` and `sshm copy` refuse the group's hosts.
- Disabled hosts are hidden from `sshm list` (use `--all`) and from shell
  completion.

Enable restores the original block text exactly as it was (the parser
remembers the verbatim bytes) and cleans up the state file. The state file
is defense-in-depth: a disabled group stays disabled even if its blocks are
removed from the config by hand.

## Config preservation

The parser preserves:
- Comments (standalone and inline)
- Blank lines
- DevPod blocks (`# DevPod Start/End` markers) — marked read-only
- Original ordering

The writer uses atomic writes (temp file + fsync + rename) and creates a timestamped backup before every write.

## Host * defaults (`sshm init`)

Generates or repairs a `Host *` block with:

- ServerAliveInterval 60, ServerAliveCountMax 3
- IdentitiesOnly yes, HashKnownHosts yes
- StrictHostKeyChecking accept-new
- Post-quantum KEX (mlkem768x25519-sha256, sntrup761x25519-sha512)
- Strong host key algorithms (ssh-ed25519, rsa-sha2-512, rsa-sha2-256)
- chacha20-poly1305, AES-GCM ciphers
- HMAC-SHA2-256/512 ETM MACs

## Project structure

```
ssh-tools/
  cmd/sshm/main.go           # entry point
  internal/
    domain/                  # pure logic: Host, Group, Validate, EffectiveConfig
    config/                  # parser, writer, backup, atomic write
    app/                     # orchestration: list, add, edit, connect, validate, dump
    cli/                     # cobra commands
    tui/                     # bubbletea TUI (list + editor)
  testdata/                  # golden files for parser tests
```

## Dependencies

- [cobra](https://github.com/spf13/cobra) — CLI framework
- [bubbletea](https://github.com/charmbracelet/bubbletea) (v2) — TUI
- [bubbles](https://github.com/charmbracelet/bubbles) (v2) — TUI components (text input)
- [lipgloss](https://github.com/charmbracelet/lipgloss) (v2) — TUI styling

## Known limitations

- **Writes normalize the whole file.** Any change made through `sshm add`, `edit`, `groups disable/enable` (or the TUI, once editing is re-enabled) re-serializes the entire config, not just the edited host: indentation becomes 2 spaces, option names get canonical casing, runs of blank lines collapse, comment lines *inside* a host block are dropped, comments between hosts are moved to the top of the file, and DevPod block options are re-ordered. A timestamped backup (`config.bak.<timestamp>`) is written next to the config before every change. Configs already in this canonical form round-trip byte-for-byte.
- The TUI cannot rename a host, edit a host's group, or edit options other than the six in the editor; use the CLI (`sshm edit --help`) or edit the file by hand.

## Development

```bash
go test ./internal/...       # run tests
go vet ./...                 # lint
go build -o bin/sshm ./cmd/sshm/
```

## License

GPL-2.0-only. See [LICENSE](LICENSE).

Same license as the Linux kernel.