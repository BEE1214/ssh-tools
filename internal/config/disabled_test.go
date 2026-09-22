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
	if deployAcq.RawBlock == "" {
		t.Error("deploy-acq-prod RawBlock should be populated")
	}
	if !strings.Contains(deployAcq.RawBlock, "HostName 192.168.1.10") {
		t.Errorf("RawBlock missing content: %q", deployAcq.RawBlock)
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

// TestWriteRoundTripDisabled checks that parse→write→parse is stable and the
// disabled block content is preserved verbatim.
func TestWriteRoundTripDisabled(t *testing.T) {
	cfg, err := Parse([]byte(disabledFixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	data, err := Write(cfg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	text := string(data)
	for _, want := range []string{
		domain.DisabledMarkerStart("deploy"),
		domain.DisabledMarkerEnd("deploy"),
		"# Host deploy-acq-prod",
		"#   HostName 192.168.1.10",
		"# Host deploy-eu-prod",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
	// Disabled host lines must be commented out (inert for raw ssh) — an
	// uncommented "Host deploy-acq-prod" line must NOT appear.
	for _, banned := range []string{"\nHost deploy-acq-prod", "\n  HostName 192.168.1.10"} {
		if strings.Contains(text, banned) {
			t.Errorf("disabled block not commented out: found %q:\n%s", banned, text)
		}
	}

	// Second pass must be identical (idempotent round-trip).
	cfg2, err := Parse(data)
	if err != nil {
		t.Fatalf("re-Parse: %v", err)
	}
	if len(cfg2.Hosts) != len(cfg.Hosts) {
		t.Fatalf("re-parse host count = %d, want %d", len(cfg2.Hosts), len(cfg.Hosts))
	}
	for i := range cfg.Hosts {
		a, b := cfg.Hosts[i], cfg2.Hosts[i]
		if a.Name != b.Name || a.Disabled != b.Disabled || a.Group != b.Group || a.RawBlock != b.RawBlock {
			t.Errorf("host %d mismatch:\n first: %+v\nsecond: %+v", i, a, b)
		}
	}
	data2, err := Write(cfg2)
	if err != nil {
		t.Fatalf("re-Write: %v", err)
	}
	if string(data2) != text {
		t.Errorf("write not idempotent:\nfirst:\n%s\nsecond:\n%s", text, data2)
	}
}

// TestWriteVerbatimRestore checks that a disabled host's content survives
// byte-for-byte (uncommented form in RawBlock, commented form on disk),
// including comments inside the block.
func TestWriteVerbatimRestore(t *testing.T) {
	input := `# sshm disabled group=x start
# # kept comment
# Host x-1
#   HostName 10.0.0.5
#   # inline comment
#   User root
# sshm disabled group=x end
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	data, err := Write(cfg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The commented block between markers must be byte-identical after a
	// parse→write cycle (round-trip stability).
	if !strings.Contains(string(data), "# # kept comment\n# Host x-1\n#   HostName 10.0.0.5\n#   # inline comment\n#   User root\n") {
		t.Errorf("commented block not preserved:\n%s", data)
	}
	// RawBlock holds the UNcommented original (what enable restores).
	if h := cfg.Hosts[0]; !strings.Contains(h.RawBlock, "Host x-1\n  HostName 10.0.0.5") {
		t.Errorf("RawBlock should hold uncommented original, got: %q", h.RawBlock)
	}
}

// TestGroupCommentRoundTrip checks that a non-redundant "# group:" comment
// survives parse→write cycles.
func TestGroupCommentRoundTrip(t *testing.T) {
	input := `# group: prod
Host web-prod-1
  HostName 10.0.0.1
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	data, err := Write(cfg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(string(data), "# group: prod\n") {
		t.Errorf("group comment lost:\n%s", data)
	}

	// Redundant comments (matching the prefix heuristic) are not re-emitted.
	cfg2, err := Parse([]byte("Host web-1\n  HostName 10.0.0.1\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg2.Hosts[0].Group = "web" // equals GroupFor("web-1")
	data2, err := Write(cfg2)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if strings.Contains(string(data2), "# group:") {
		t.Errorf("redundant group comment should be omitted:\n%s", data2)
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