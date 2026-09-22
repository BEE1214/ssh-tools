# sshm — SSH Config Manager

TUI and CLI tool for managing `~/.ssh/config`. Reads and writes your SSH config directly — no database, no shadow state, no separate format.

> **Warning:** This project is AI-generated. The code, tests, and documentation
> were produced with the assistance of AI tools. Review before relying on it
> for anything important.

## Status

Phase 1 complete: CLI working, TUI pending.

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
sshm                         # launch TUI (pending)
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
    tui/                     # bubbletea TUI (pending)
  testdata/                  # golden files for parser tests
```

## Dependencies

- [cobra](https://github.com/spf13/cobra) — CLI framework
- [bubbletea](https://github.com/charmbracelet/bubbletea) — TUI (pending)
- [bubbles](https://github.com/charmbracelet/bubbles) — TUI components (pending)
- [lipgloss](https://github.com/charmbracelet/lipgloss) — TUI styling (pending)

## Development

```bash
go test ./internal/...       # run tests (36 passing)
go vet ./...                 # lint
go build -o bin/sshm ./cmd/sshm/
```

## License

GPL-2.0-only. See [LICENSE](LICENSE).

Same license as the Linux kernel.