package config

import (
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

func hostNames(cfg *ConfigFile) []string {
	names := make([]string, len(cfg.Hosts))
	for i, h := range cfg.Hosts {
		names[i] = h.Name
	}
	return names
}

// TestParseDanglingStartMarker: an unterminated start marker must fail the
// parse loudly rather than swallowing every later host (a save would then
// delete them).
func TestParseDanglingStartMarker(t *testing.T) {
	in := "Host a\n  HostName 10.0.0.1\n\n" +
		domain.DisabledMarkerStart("grp") + "\n" +
		"Host b\n  HostName 10.0.0.2\n\n" +
		"Host c\n  HostName 10.0.0.3\n"
	cfg, err := Parse([]byte(in))
	if err == nil {
		t.Fatalf("Parse succeeded with dangling start marker; hosts = %v", hostNames(cfg))
	}
	if !strings.Contains(err.Error(), "unterminated") {
		t.Errorf("error should mention unterminated block, got: %v", err)
	}
}

// TestParseStrayEndMarker: an end marker with no open block is an ordinary
// comment and loses nothing.
func TestParseStrayEndMarker(t *testing.T) {
	in := "Host a\n  HostName 10.0.0.1\n\n" +
		domain.DisabledMarkerEnd("grp") + "\n" +
		"Host b\n  HostName 10.0.0.2\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := hostNames(cfg); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("hosts = %v, want [a b]", got)
	}
	for _, h := range cfg.Hosts {
		if h.Disabled {
			t.Errorf("host %q wrongly disabled", h.Name)
		}
	}
	out, err := Write(cfg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(string(out), domain.DisabledMarkerEnd("grp")) {
		t.Errorf("stray end marker comment lost on write:\n%s", out)
	}
}

// TestParseNestedStartMarker: a start marker inside an open disabled block
// is a raw line of that block, not a new block.
func TestParseNestedStartMarker(t *testing.T) {
	in := domain.DisabledMarkerStart("outer") + "\n" +
		"# Host x\n#   HostName 10.0.0.1\n" +
		domain.DisabledMarkerStart("inner") + "\n" +
		domain.DisabledMarkerEnd("outer") + "\n" +
		"Host after\n  HostName 10.0.0.9\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := hostNames(cfg); len(got) != 2 || got[0] != "x" || got[1] != "after" {
		t.Fatalf("hosts = %v, want [x after]", got)
	}
	if !cfg.Hosts[0].Disabled || cfg.Hosts[0].Group != "outer" {
		t.Errorf("x = %+v, want disabled in group outer", cfg.Hosts[0])
	}
	if cfg.Hosts[1].Disabled {
		t.Errorf("host after the block must stay enabled")
	}

	// Nested start without a closing end for the outer block still fails loudly.
	in = domain.DisabledMarkerStart("outer") + "\n# Host x\n" + domain.DisabledMarkerStart("inner") + "\n" +
		domain.DisabledMarkerEnd("inner") + "\nHost after\n"
	if _, err := Parse([]byte(in)); err == nil {
		t.Error("Parse should fail: outer block never closed")
	}
}

// TestParseMismatchedEndMarker: an end marker for another group does not
// close the open block.
func TestParseMismatchedEndMarker(t *testing.T) {
	in := domain.DisabledMarkerStart("a") + "\n# Host x\n#   HostName 10.0.0.1\n" +
		domain.DisabledMarkerEnd("b") + "\n" +
		"Host after\n  HostName 10.0.0.9\n"
	if _, err := Parse([]byte(in)); err == nil {
		t.Fatal("Parse should fail: block a is never closed (end marker names group b)")
	}

	// With the right end marker later, the foreign end marker stays inside the block.
	in += domain.DisabledMarkerEnd("a") + "\nHost tail\n  HostName 10.0.0.8\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var tail bool
	for _, h := range cfg.Hosts {
		if h.Name == "tail" && !h.Disabled {
			tail = true
		}
	}
	if !tail {
		t.Errorf("host after the properly closed block lost: %v", hostNames(cfg))
	}
}

// TestParseMarkerInsideHostBlock: a marker-looking comment inside an enabled
// host block is just a comment — later hosts survive.
func TestParseMarkerInsideHostBlock(t *testing.T) {
	in := "Host a\n  HostName 10.0.0.1\n" +
		domain.DisabledMarkerStart("grp") + "\n" +
		"  User root\n\n" +
		"Host b\n  HostName 10.0.0.2\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := hostNames(cfg); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("hosts = %v, want [a b]", got)
	}
	if cfg.Hosts[0].User != "root" {
		t.Errorf("host a lost options after the comment: %+v", cfg.Hosts[0])
	}
	for _, h := range cfg.Hosts {
		if h.Disabled {
			t.Errorf("host %q wrongly disabled", h.Name)
		}
	}
}

// TestParseWriteRoundTripMalformedMarkers: Parse→Write never drops hosts when
// markers are malformed but the file is accepted.
func TestParseWriteRoundTripMalformedMarkers(t *testing.T) {
	in := "Host a\n  HostName 10.0.0.1\n" +
		domain.DisabledMarkerStart("grp") + "\n" +
		"\n" +
		domain.DisabledMarkerEnd("other") + "\n" +
		"Host b\n  HostName 10.0.0.2\n\n" +
		domain.DisabledMarkerEnd("grp") + "\n" +
		"Host c\n  HostName 10.0.0.3\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out, err := Write(cfg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	cfg2, err := Parse(out)
	if err != nil {
		t.Fatalf("re-Parse: %v", err)
	}
	for _, want := range []string{"a", "b", "c"} {
		found := false
		for _, n := range hostNames(cfg2) {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("host %q lost in round-trip: %v\n%s", want, hostNames(cfg2), out)
		}
	}
}
