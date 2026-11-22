package config

import (
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

const disabledFixture = `# top comment
Host web-1
  HostName 10.0.0.1
  User admin

# sshm disabled group=deploy start
# Host deploy-acq-prod
#   HostName 192.168.1.10
#   User deploy
#   Port 22
#
# # group: deploy
# Host deploy-eu-prod
#   HostName 192.168.1.11
#   User deploy
# sshm disabled group=deploy end
# comment directly after markers
Host misc-1
  HostName 10.0.0.9
`

// TestParseDisabledMarkers checks that host blocks between disable markers
// are parsed as Disabled hosts with the marker's group name.
func TestParseDisabledMarkers(t *testing.T) {
	cfg, err := Parse([]byte(disabledFixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := len(cfg.Hosts); got != 4 {
		t.Fatalf("len(Hosts) = %d, want 4 (web-1, 2x deploy, misc-1)", got)
	}

	byName := map[string]domain.Host{}
	for _, h := range cfg.Hosts {
		byName[h.Name] = h
	}

	deployAcq, ok := byName["deploy-acq-prod"]
	if !ok {
		t.Fatal("deploy-acq-prod not parsed")
	}
	if !deployAcq.Disabled {
		t.Error("deploy-acq-prod should be Disabled")
	}
	if deployAcq.Group != "deploy" {
		t.Errorf("deploy-acq-prod Group = %q, want deploy", deployAcq.Group)
	}
	if deployAcq.HostName != "192.168.1.10" {
		t.Errorf("deploy-acq-prod HostName = %q, want 192.168.1.10", deployAcq.HostName)
	}
	if deployAcq.User != "deploy" || deployAcq.Port != "22" {
		t.Errorf("deploy-acq-prod options not parsed: User=%q Port=%q", deployAcq.User, deployAcq.Port)
	}

	deployEu, ok := byName["deploy-eu-prod"]
	if !ok {
		t.Fatal("deploy-eu-prod not parsed")
	}
	if !deployEu.Disabled {
		t.Error("deploy-eu-prod should be Disabled")
	}
	if deployEu.Group != "deploy" {
		t.Errorf("deploy-eu-prod Group = %q, want deploy (from marker)", deployEu.Group)
	}

	// Enabled hosts must not be flagged.
	for _, name := range []string{"web-1", "misc-1"} {
		if h := byName[name]; h.Disabled {
			t.Errorf("%s should not be Disabled", name)
		}
	}

	// Line coordinates of enabled hosts must be tracked normally.
	if h := byName["web-1"]; h.LineStart <= 0 || h.LineEnd < h.LineStart {
		t.Errorf("web-1 line range invalid: %d-%d", h.LineStart, h.LineEnd)
	}
	if h := byName["deploy-acq-prod"]; h.LineStart >= 0 {
		t.Errorf("disabled host LineStart should be negative, got %d", h.LineStart)
	}
}

// TestParseGroupComment checks that "# group: <name>" above a Host line is
// honored and consumed.
func TestParseGroupComment(t *testing.T) {
	input := `# group: prod
Host web-prod-1
  HostName 10.0.0.1

Host web-2
  HostName 10.0.0.2
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("len(Hosts) = %d, want 2", len(cfg.Hosts))
	}
	if cfg.Hosts[0].Group != "prod" {
		t.Errorf("Hosts[0].Group = %q, want prod (explicit comment)", cfg.Hosts[0].Group)
	}
	if cfg.Hosts[1].Group != "web" {
		t.Errorf("Hosts[1].Group = %q, want web (prefix fallback)", cfg.Hosts[1].Group)
	}
}

// TestGroupCommentInBlockLines checks that a non-redundant "# group:" comment
// of a parsed host is part of the canonical block BlockLines renders.
func TestGroupCommentInBlockLines(t *testing.T) {
	input := `# group: prod
Host web-prod-1
  HostName 10.0.0.1
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	lines, err := BlockLines(cfg.Hosts[0])
	if err != nil {
		t.Fatalf("BlockLines: %v", err)
	}
	if got := strings.Join(lines, "\n"); !strings.Contains(got, "# group: prod\n") {
		t.Errorf("group comment lost:\n%s", got)
	}

	// Redundant comments (matching the prefix heuristic) are not emitted.
	cfg2, err := Parse([]byte("Host web-1\n  HostName 10.0.0.1\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg2.Hosts[0].Group = "web" // equals GroupFor("web-1")
	lines2, err := BlockLines(cfg2.Hosts[0])
	if err != nil {
		t.Fatalf("BlockLines: %v", err)
	}
	if got := strings.Join(lines2, "\n"); strings.Contains(got, "# group:") {
		t.Errorf("redundant group comment should be omitted:\n%s", got)
	}
}

// TestParseMultipleDisabledGroups checks two disabled groups in one file.
func TestParseMultipleDisabledGroups(t *testing.T) {
	input := `# sshm disabled group=deploy start
# Host deploy-a
#   HostName 10.0.0.1
# sshm disabled group=deploy end
# sshm disabled group=prod start
# Host prod-a
#   HostName 10.0.0.2
# sshm disabled group=prod end
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("len(Hosts) = %d, want 2", len(cfg.Hosts))
	}
	if cfg.Hosts[0].Group != "deploy" || !cfg.Hosts[0].Disabled {
		t.Errorf("deploy-a wrong: Group=%q Disabled=%v", cfg.Hosts[0].Group, cfg.Hosts[0].Disabled)
	}
	if cfg.Hosts[1].Group != "prod" || !cfg.Hosts[1].Disabled {
		t.Errorf("prod-a wrong: Group=%q Disabled=%v", cfg.Hosts[1].Group, cfg.Hosts[1].Disabled)
	}
}