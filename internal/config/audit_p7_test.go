package config

// Mutation-audit tests for P7 (see PLAN-p7.md section 3/X1: the helpers that
// survive the removal of config.Write).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// NewestBackup answers with a backup FILE: a directory (or anything that is not
// a regular file) that happens to carry a backup-like name is not a backup.
func TestAuditP7_NewestBackupIgnoresNonRegularEntries(t *testing.T) {
	dir := t.TempDir()
	older := filepath.Join(dir, "sshm.conf.20240101-090000.000000")
	if err := os.WriteFile(older, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sshm.conf.20250101-090000.000000"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(older, filepath.Join(dir, "sshm.conf.20260101-090000.000000")); err != nil {
		t.Fatal(err)
	}
	got, ok := NewestBackup(dir, "sshm.conf")
	if !ok || got != older {
		t.Errorf("NewestBackup = %q, %v; want the regular file %q", got, ok, older)
	}
}

// The group comment and the line-break guard of the block text that Doc.AppendBlock
// and init write (BlockLines is what is left of the removed writer).
func TestAuditP7_BlockLinesRefuseLineBreaksInEveryField(t *testing.T) {
	for _, brk := range []string{"\n", "\r"} {
		name := "CR"
		if brk == "\n" {
			name = "LF"
		}
		set := map[string]func(h *domain.Host){
			"Group":           func(h *domain.Host) { h.Group = "a" + brk + "b" },
			"HostName":        func(h *domain.Host) { h.HostName = "a" + brk + "b" },
			"User":            func(h *domain.Host) { h.User = "a" + brk + "b" },
			"IdentityFile":    func(h *domain.Host) { h.IdentityFile = "a" + brk + "b" },
			"IdentityFiles":   func(h *domain.Host) { h.IdentityFiles = []string{"a" + brk + "b"} },
			"CertificateFile": func(h *domain.Host) { h.CertificateFile = "a" + brk + "b" },
			"CertFiles":       func(h *domain.Host) { h.CertificateFiles = []string{"a" + brk + "b"} },
			"ProxyJump":       func(h *domain.Host) { h.ProxyJump = "a" + brk + "b" },
			"ProxyCommand":    func(h *domain.Host) { h.ProxyCommand = "a" + brk + "b" },
			"LocalForwards":   func(h *domain.Host) { h.LocalForwards = []string{"a" + brk + "b"} },
			"RemoteForwards":  func(h *domain.Host) { h.RemoteForwards = []string{"a" + brk + "b"} },
			"DynamicForwards": func(h *domain.Host) { h.DynamicForwards = []string{"a" + brk + "b"} },
			"ExtraValue":      func(h *domain.Host) { h.Extra = map[string]string{"Key": "a" + brk + "b"} },
			"ExtraKey":        func(h *domain.Host) { h.Extra = map[string]string{"Key" + brk + "X": "v"} },
			"Ciphers":         func(h *domain.Host) { h.Ciphers = "a" + brk + "b" },
		}
		for field, fn := range set {
			t.Run(name+"/"+field, func(t *testing.T) {
				h := domain.Host{Name: "lb-1"}
				fn(&h)
				lines, err := BlockLines(h)
				if err == nil {
					t.Fatalf("BlockLines accepted a line break in %s:\n%s", field, strings.Join(lines, "\n"))
				}
			})
		}
	}
}

func TestAuditP7_BlockLinesGroupComment(t *testing.T) {
	has := func(lines []string) bool {
		for _, l := range lines {
			if strings.HasPrefix(l, domain.GroupCommentPrefix) {
				return true
			}
		}
		return false
	}
	cases := []struct {
		name string
		h    domain.Host
		want bool
	}{
		{"explicit group that differs from the derived one", domain.Host{Name: "web-1", Group: "ops-team"}, true},
		{"group equal to the derived one", domain.Host{Name: "web-1", Group: domain.GroupFor("web-1")}, false},
		{"no group", domain.Host{Name: "web-1"}, false},
		{"disabled block (the markers carry the group)", domain.Host{Name: "web-1", Group: "ops-team", Disabled: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines, err := BlockLines(c.h)
			if err != nil {
				t.Fatal(err)
			}
			if got := has(lines); got != c.want {
				t.Errorf("group comment present = %v, want %v:\n%s", got, c.want, strings.Join(lines, "\n"))
			}
		})
	}
}
