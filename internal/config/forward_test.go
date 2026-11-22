package config

import "testing"

const forwardsFixture = `Host *
  LocalForward 9000 127.0.0.1:9000
  LocalForward 9001 127.0.0.1:9001

Host jump
  HostName 10.0.0.5
  RemoteForward 8080 localhost:80
  DynamicForward 1080
`

// TestParseForwards checks that repeated LocalForward/RemoteForward/
// DynamicForward lines are all kept (not folded first-wins like Extra).
func TestParseForwards(t *testing.T) {
	cfg, err := Parse([]byte(forwardsFixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("len(Hosts) = %d, want 2", len(cfg.Hosts))
	}

	wildcard := cfg.Hosts[0]
	if got := len(wildcard.LocalForwards); got != 2 {
		t.Fatalf("wildcard LocalForwards count = %d, want 2: %v", got, wildcard.LocalForwards)
	}
	if wildcard.LocalForwards[0] != "9000 127.0.0.1:9000" {
		t.Errorf("LocalForwards[0] = %q", wildcard.LocalForwards[0])
	}
	if wildcard.LocalForwards[1] != "9001 127.0.0.1:9001" {
		t.Errorf("LocalForwards[1] = %q", wildcard.LocalForwards[1])
	}

	jump := cfg.Hosts[1]
	if len(jump.RemoteForwards) != 1 || jump.RemoteForwards[0] != "8080 localhost:80" {
		t.Errorf("jump RemoteForwards = %v", jump.RemoteForwards)
	}
	if len(jump.DynamicForwards) != 1 || jump.DynamicForwards[0] != "1080" {
		t.Errorf("jump DynamicForwards = %v", jump.DynamicForwards)
	}
}

// TestParseForwards_WhitespaceNormalized checks that extra internal
// whitespace in a forward value is collapsed to a single space so stored
// entries are stable regardless of source formatting.
func TestParseForwards_WhitespaceNormalized(t *testing.T) {
	cfg, err := Parse([]byte("Host jump\n  LocalForward 9000   127.0.0.1:9000\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Hosts[0].LocalForwards[0]; got != "9000 127.0.0.1:9000" {
		t.Errorf("LocalForwards[0] = %q, want normalized single-space form", got)
	}
}
