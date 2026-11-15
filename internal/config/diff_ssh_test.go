package config

import (
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// sshG runs `ssh -F cfg -G host` and returns the lower-cased key -> values
// map of its output. Only `-G` is used: it prints the resolved config and
// never connects.
func sshG(t *testing.T, cfg, host string) map[string][]string {
	t.Helper()
	out, err := exec.Command("ssh", "-F", cfg, "-G", host).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G %s: %v\n%s", host, err, out)
	}
	res := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			res[k] = append(res[k], v)
		}
	}
	return res
}

// diffScenario is one generated multi-file config. "@@" in file contents is
// replaced by the temp dir so every Include path is absolute. The main file
// is always "config". names lists the host names to resolve (they need not
// have a block of their own; pattern blocks may be the only match).
type diffScenario struct {
	name  string
	files map[string]string
	names []string
}

var diffScenarios = []diffScenario{
	{
		// Include at the top, "Host *" defaults after: the included block is
		// evaluated first and wins for what it sets; the defaults fill the rest.
		name: "include-top-star-after",
		files: map[string]string{
			"inc/top.conf": `Include @@/inc/nested.conf

Host inc-a
  HostName 10.0.1.1
  User inc-user
  Port 2201
  IdentityFile @@/id_inc_a
  LocalForward 9001 192.0.2.10:80
`,
			"inc/nested.conf": `Host inc-nested
  HostName 10.0.2.1
  IdentityFile @@/id_nested
`,
			"config": `Include @@/inc/top.conf

Host main-1
  HostName 10.0.0.1
  User main-user
  IdentityFile @@/id_main1
  LocalForward 9002 192.0.2.11:80

Host *
  User fallback
  Port 2200
  IdentityFile @@/id_default
  LocalForward 9001 192.0.2.10:80
  LocalForward 9003 192.0.2.12:80
`,
		},
		names: []string{"inc-a", "inc-nested", "main-1", "other"},
	},
	{
		// "Host *" first, Include after: the defaults shadow every later
		// scalar (ssh is first-wins) while lists still accumulate.
		name: "star-first-include-after",
		files: map[string]string{
			"inc/after.conf": `Host inc-late
  HostName 10.0.3.1
  User late-user
  Port 2203
  IdentityFile @@/id_late
  LocalForward 9011 192.0.2.21:80
`,
			"config": `Host *
  User fallback
  Port 2200
  IdentityFile @@/id_default
  LocalForward 9010 192.0.2.20:80

Include @@/inc/after.conf

Host main-1
  HostName 10.0.0.1
  User mainuser
  IdentityFile @@/id_main1
  LocalForward 9010 192.0.2.20:80
`,
		},
		names: []string{"main-1", "inc-late"},
	},
	{
		name: "wildcard-specific-before",
		files: map[string]string{
			"config": `Host web-1
  HostName 10.0.4.1
  User exact
  IdentityFile @@/id_exact

Host web-*
  User wild
  Port 2204
  IdentityFile @@/id_wild
  LocalForward 9020 192.0.2.30:80

Host *
  User star
  Port 2200
  Compression yes
`,
		},
		names: []string{"web-1", "web-2"},
	},
	{
		name: "wildcard-specific-after",
		files: map[string]string{
			"config": `Host web-*
  User wild
  Port 2204
  IdentityFile @@/id_wild
  LocalForward 9020 192.0.2.30:80

Host w?b-1
  User question
  Port 2205
  LocalForward 9021 192.0.2.31:80

Host web-1
  HostName 10.0.4.1
  User exact
  Port 2206
  IdentityFile @@/id_exact
  LocalForward 9020 192.0.2.30:80

Host *-2
  HostName 10.0.4.2
  Port 2207

Host *
  User star
  IdentityFile @@/id_default
`,
		},
		names: []string{"web-1", "web-2", "wxb-1"},
	},
	{
		name: "negation",
		files: map[string]string{
			"config": `Host * !secret-1 !db-?
  User open
  Port 2208
  IdentityFile @@/id_open
  LocalForward 9030 192.0.2.40:80

Host secret-1 db-1 db-22 plain
  HostName 10.0.5.1
  Port 2209

Host db-? web-1
  User dbweb
  IdentityFile @@/id_dbweb

Host *
  User star
  IdentityFile @@/id_default
`,
		},
		names: []string{"secret-1", "db-1", "db-22", "plain", "web-1", "other"},
	},
	{
		// P2c item 1: Host lines with quotes, escapes and inline comments.
		// Matching goes by Host.Patterns (what ssh reads), not by the raw
		// text in Host.Name.
		name: "quoted-and-commented-host-lines",
		files: map[string]string{
			"config": `Host "q one" q-two # trailing words
  User quoted
  Port 2212

Host # nothing here
  User nobody

Host q\ three q-four
  User escaped
  IdentityFile @@/id_escaped

Host *
  User star
  IdentityFile @@/id_default
`,
		},
		names: []string{"q-two", "q-four", "q", "one", "three", "trailing", "words", "nothing", "here", "other"},
	},
	{
		// P2c item 6: disabled-group markers directly below host blocks. An
		// unterminated start marker and a pair around active lines are just
		// comments (the options around them belong to the block); after an
		// inert region the block above goes on.
		name: "markers-below-host-blocks",
		files: map[string]string{
			"config": `Host mk-a
  HostName 10.0.6.1
# sshm disabled group=pair start
  Port 2210
# sshm disabled group=pair end
  IdentityFile @@/id_mk_a

Host mk-b
  HostName 10.0.6.2
# sshm disabled group=inert start
# Host mk-off
#   User off
# sshm disabled group=inert end
  Port 2211
  LocalForward 9040 192.0.2.50:80

Host mk-c
  HostName 10.0.6.3
# sshm disabled group=dangling start
  User marker-user
  IdentityFile @@/id_mk_c

Host *
  User star
  IdentityFile @@/id_default
`,
		},
		names: []string{"mk-a", "mk-b", "mk-c", "other"},
	},
}

// TestDifferentialAgainstSSH compares sshm's view of generated multi-file
// configs (Load + domain.EffectiveConfig) with `ssh -F <main> -G <host>`.
//
// Compared: hostname, user, port as scalars (first match wins, like ssh),
// identityfile (EffectiveConfig.IdentityFiles) and localforward as SETS (list
// options: every matching block contributes, repeated lines accumulate).
//
// Remaining, documented differences (not hidden by the test):
//
//  1. An Include below a "Host x" line is conditional in ssh (only applies
//     while x matches); sshm follows it unconditionally. Fixtures put every
//     Include above the first Host or inside an always-true "Host *" region.
//  2. Defaults: ssh fills in port 22 and the login user; sshm leaves them
//     empty. Every fixture host gets User from some block, Port ""==22, and
//     an unset HostName resolves to the host name itself.
//  3. Match blocks are out of scope and not used.
func TestDifferentialAgainstSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}

	for _, sc := range diffScenarios {
		t.Run(sc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range sc.files {
				write(t, filepath.Join(dir, rel), strings.ReplaceAll(content, "@@", dir))
			}
			main := filepath.Join(dir, "config")

			l, err := Load(main)
			if err != nil {
				t.Fatal(err)
			}
			if len(l.Warnings) != 0 {
				t.Fatalf("warnings: %v", l.Warnings)
			}

			for _, name := range sc.names {
				t.Run(name, func(t *testing.T) {
					ssh := sshG(t, main, name)
					mine, err := domain.EffectiveConfig(l.Hosts, name)
					if err != nil {
						t.Fatal(err)
					}

					if got, want := orDefault(mine.HostName, name), first(ssh["hostname"]); got != want {
						t.Errorf("hostname: sshm %q, ssh %q", got, want)
					}
					if got, want := orDefault(mine.Port, "22"), first(ssh["port"]); got != want {
						t.Errorf("port: sshm %q, ssh %q", got, want)
					}
					if got, want := mine.User, first(ssh["user"]); got != want {
						t.Errorf("user: sshm %q, ssh %q", got, want)
					}

					assertSetEqual(t, "identityfile", mine.IdentityFiles, ssh["identityfile"])
					if got, want := mine.IdentityFile, first(ssh["identityfile"]); got != want {
						t.Errorf("first identityfile: sshm %q, ssh %q", got, want)
					}

					// ssh -G prints "[host]:port" brackets; strip them to compare.
					var wantFwd []string
					for _, f := range ssh["localforward"] {
						wantFwd = append(wantFwd, stripBrackets(f))
					}
					assertSetEqual(t, "localforward", mine.LocalForwards, wantFwd)
				})
			}
		})
	}
}

func assertSetEqual(t *testing.T, what string, got, want []string) {
	t.Helper()
	g, w := uniqSorted(got), uniqSorted(want)
	if strings.Join(g, "\n") != strings.Join(w, "\n") {
		t.Errorf("%s set: sshm %v, ssh %v", what, g, w)
	}
}

func stripBrackets(s string) string {
	return strings.NewReplacer("[", "", "]", "").Replace(s)
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
