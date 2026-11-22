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
sshm dump <hostname>         # effective config (like ssh -G: first match wins)
sshm validate                # lint config, report issues
sshm groups                  # list groups + enable/disable state
sshm groups disable <group>  # disable a group (hard gate, see below)
sshm groups enable <group>   # re-enable a disabled group
sshm init                    # fresh machine: set up sshm; set-up config: add the Host * defaults block
sshm setup [--dry-run]       # keep sshm's hosts in ~/.ssh/config.d/sshm.conf (one Include line is added to the ssh config)
sshm import [--apply]        # move plain Host blocks into that file (dry run unless --apply)
```

Every command that writes an ssh config (`add`, `edit`, `forward --save`/`--clear`, `cert sign <host>`, `cert revoke` of a certificate a host references, `groups disable`/`enable`, `init`, and the editing keys of the TUI) needs the setup below. Without it they change nothing and fail with `sshm is not set up: run 'sshm setup' first`. Commands that only read (`list`, `search`, `dump`, `connect`, `copy`, `validate`, `groups`, `cert list`/`inspect`) work on any ssh config.

A group state file `<ssh config>.sshm-groups` of an earlier sshm is not migrated by `setup`; `import` moves it for the groups it moves. A comment directly above a `Host` line (no blank line between) moves with that host on `import`, including a file-header comment that touches the first host.

## First run

sshm writes only to its own file, `~/.ssh/config.d/sshm.conf`, which your ssh config includes with one `Include` line (as line 1, so that it applies to every host). Your own file is never re-serialized.

- **A machine without an ssh config:** `sshm init` creates `~/.ssh` (0700), `config.d/sshm.conf` (empty) and an ssh config that holds the `Include` line, checks with `ssh -G` that ssh accepts the result, and stops. It prints what it created; run `sshm init` again to add the default `Host *` block.
- **An existing ssh config:** `sshm setup` adds the `Include` line and creates the managed file (`sshm setup --dry-run` shows what it would do). Then `sshm import` (dry run) and `sshm import --apply` move the plain `Host` blocks you want sshm to manage into the managed file. Hosts that stay in your file are still listed, connected to and validated; they just cannot be edited by sshm (it says where they are defined).

Every write is made by changing lines of the managed file, then asking `ssh -G` for every host before and after: a change that alters anything it should not, or that ssh rejects, is rolled back. A backup of the file goes to `~/.ssh/sshm-backups/` first (the newest 20 per file are kept). SIGINT, SIGTERM or SIGHUP while a save is being verified roll it back too (`interrupted: <file> restored`), so ssh never keeps a half-checked file. If ssh already rejects your configuration, sshm refuses to write and names the newest backup of the file.

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

On a set-up config (see [First run](#first-run)) the TUI edits too: `e` edit, `n` new, `d` duplicate, `D` delete (asks `y`/`n`). On a config that is not set up the four keys only show a notice (`editing needs setup: run 'sshm setup' ...`) and change nothing. A host that sshm cannot edit (defined in your own file or an included file, or on a `Host` line with several patterns) shows the reason when you press one of them.

In the editor: `Tab`/`Shift+Tab` move between fields, `Enter` on the last field or `Ctrl+S` saves, `Esc` cancels. Validation errors block the save and are shown inline; warnings (e.g. no `IdentityFile`) are shown but do not block.

- Hosts in a disabled group are shown dimmed with a `[disabled]` tag and cannot be connected to, edited or deleted. Enable the group with `sshm groups enable <group>`.
- DevPod hosts are tagged `[read-only]`: you can connect to them, but not edit, duplicate or delete them.
- The host name is read-only when editing (there is no rename operation); to rename, duplicate and delete.
- The status bar shows the number of validation warnings/errors in the config (`sshm validate` lists them).
- All changes go through the same code path as the CLI: the managed file is re-read, a backup is written, and the new content is verified with `ssh -G` and written atomically. The TUI never overwrites changes made to the file while it is open.

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

- The group's host blocks are commented out of the managed file
  (`~/.ssh/config.d/sshm.conf`) between
  `# sshm disabled group=<name> start/end` markers — raw `ssh <host>` no
  longer resolves them. Every member of the group must be defined in the
  managed file; otherwise disable is refused and says which hosts to import.
- The group is recorded in `~/.ssh/config.d/sshm.conf.sshm-groups` (sidecar state).
- `sshm connect <host>` and `sshm copy` refuse the group's hosts.
- Disabled hosts are hidden from `sshm list` (use `--all`) and from shell
  completion.

Enable restores the original block text exactly as it was (the block is only
commented out, never rewritten) and cleans up the state file. The state file
is defense-in-depth: a disabled group stays disabled even if its blocks are
removed from the config by hand.

## Config preservation

sshm edits the managed file line by line, so everything it does not change stays byte-for-byte: comments (standalone and inline), blank lines, indentation, the casing of option names and the order of the blocks. DevPod blocks (`# DevPod Start/End` markers) are read-only. Writes are atomic (temp file + fsync + rename) and every write of an existing file is preceded by a timestamped backup in `~/.ssh/sshm-backups/`.

## Host * defaults (`sshm init`)

On a set-up config, adds a `Host *` block. It is appended as the **last** host block of your ssh config: ssh uses the first value found for each option, so a catch-all `Host *` only supplies defaults when it comes after your specific hosts (a leading `Host *` would override every per-host value). If any loaded file already has a `Host *` block, `sshm init` writes nothing and prints a note on stderr saying where it is: sshm does not rewrite it, edit it by hand to change the defaults. The block contains:

- ServerAliveInterval 60, ServerAliveCountMax 3
- IdentitiesOnly yes, HashKnownHosts yes
- StrictHostKeyChecking accept-new
- Post-quantum KEX (mlkem768x25519-sha256, sntrup761x25519-sha512) and curve25519
- Strong host key algorithms (ssh-ed25519, rsa-sha2-512, rsa-sha2-256)
- chacha20-poly1305, AES-GCM ciphers
- HMAC-SHA2-256/512 ETM MACs

The algorithm lists are **filtered through what your ssh supports** (`ssh -Q kex|cipher|mac|key-sig`): preferred names your ssh does not know are dropped, because ssh refuses to run at all with one unknown algorithm name in the config. If `ssh -Q` is unavailable (or nothing from a list is supported), that option is left out and OpenSSH's defaults apply. `sshm validate` reports any algorithm name in your config that your ssh does not know (`bad-algorithm`).

## Project structure

```
ssh-tools/
  cmd/sshm/main.go           # entry point
  internal/
    domain/                  # pure logic: Host, Group, Validate, EffectiveConfig
    config/                  # parser, line-based Doc editor, backup, atomic write
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

- **Multi-pattern `Host` lines cannot be edited.** A block such as `Host db-1 db-2` is read and connectable, but sshm refuses to edit, duplicate or delete it (`"Host db-1 db-2" in <file> has several patterns, which sshm cannot edit`), and `import` does not move it. Split the line by hand.
- **Some blocks stay in your own file.** DevPod blocks, `Match` blocks, `Host *` and anything in an included file are never moved or edited by sshm; hosts defined there are read-only in the TUI and refused by the write commands.
- **Clients that do not follow `Include` do not see the managed hosts.** OpenSSH and tools that call it do; a library or tool that parses `~/.ssh/config` itself instead of asking ssh (paramiko's config parser was checked) does not read `config.d/sshm.conf` and so does not see the hosts that sshm manages.
- **A dotfile manager that overwrites the main file drops the `Include` line.** The managed hosts then vanish from ssh and every write command fails with `sshm is not set up` until you run `sshm setup` again. Keep the `Include` line in the file the manager deploys.
- **SIGKILL during a save cannot be handled.** SIGINT, SIGTERM and SIGHUP roll an unfinished save back; a process killed with SIGKILL (or a power cut) between the write and its verification can leave the managed file as written. sshm then refuses further writes ("the current ssh configuration is already broken") and names the newest backup in `~/.ssh/sshm-backups/`, which you can copy back.
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