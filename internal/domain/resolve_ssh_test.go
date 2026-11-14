package domain

import "testing"

func TestMatchPattern_Extended(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"web?", "web1", true},
		{"web?", "web", false},
		{"web?", "web12", false},
		{"??", "ab", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abcd", false},
		{"*-dev-*", "host-dev-1", true},
		{"*-dev-*", "host-prod-1", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXcYb", false},
		{"h*?", "h", false},
		{"h*?", "hx", true},
		{"*.example.org", "a.example.org", true},
		// negation: a positive match is required, any negated match excludes
		{"* !secret", "web", true},
		{"* !secret", "secret", false},
		{"!secret", "web", false}, // negation alone never matches
		{"!secret *", "secret", false},
		{"web-* !web-bad", "web-ok", true},
		{"web-* !web-bad", "web-bad", false},
		{"web-* !web-*-x", "web-a-x", false},
		{"a b !c", "b", true},
		{"a b !c", "c", false},
		{"a b !c", "d", false},
		{"", "x", false},
		// case-sensitive, like ssh Host matching
		{"Web", "web", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.name, func(t *testing.T) {
			if got := matchPattern(tt.pattern, tt.name); got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}

func TestEffectiveConfig_FirstWins(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []Host
		host     string
		wantUser string
		wantPort string
	}{
		{
			name: "Host * first beats specific",
			hosts: []Host{
				{Name: "*", User: "fallback", Port: "2200"},
				{Name: "main-1", User: "mainuser"},
			},
			host: "main-1", wantUser: "fallback", wantPort: "2200",
		},
		{
			name: "specific first beats Host *",
			hosts: []Host{
				{Name: "main-1", User: "mainuser"},
				{Name: "*", User: "fallback", Port: "2200"},
			},
			host: "main-1", wantUser: "mainuser", wantPort: "2200",
		},
		{
			name: "multiple wildcard blocks: earliest wins per option",
			hosts: []Host{
				{Name: "web-*", Port: "2201"},
				{Name: "w*", User: "wuser", Port: "2202"},
				{Name: "*", User: "star", Port: "2203"},
			},
			host: "web-1", wantUser: "wuser", wantPort: "2201",
		},
		{
			name: "non-matching blocks ignored",
			hosts: []Host{
				{Name: "db-*", User: "dbuser"},
				{Name: "web-*", User: "webuser"},
			},
			host: "web-1", wantUser: "webuser",
		},
		{
			name: "negation excludes the first block",
			hosts: []Host{
				{Name: "* !web-1", User: "others"},
				{Name: "*", User: "star"},
			},
			host: "web-1", wantUser: "star",
		},
		{
			name: "multi-pattern line with ?",
			hosts: []Host{
				{Name: "db-? web-?", User: "pair"},
				{Name: "*", User: "star"},
			},
			host: "web-1", wantUser: "pair",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EffectiveConfig(tt.hosts, tt.host)
			if err != nil {
				t.Fatal(err)
			}
			if got.User != tt.wantUser || got.Port != tt.wantPort {
				t.Errorf("User/Port = %q/%q, want %q/%q", got.User, got.Port, tt.wantUser, tt.wantPort)
			}
			if got.Name != tt.host {
				t.Errorf("Name = %q, want %q", got.Name, tt.host)
			}
		})
	}
}

func TestEffectiveConfig_NegationOnlyNotFound(t *testing.T) {
	hosts := []Host{{Name: "* !secret", User: "u"}}
	if _, err := EffectiveConfig(hosts, "secret"); err != ErrHostNotFound {
		t.Errorf("err = %v, want ErrHostNotFound", err)
	}
}

func TestEffectiveConfig_ListsAccumulateDedup(t *testing.T) {
	hosts := []Host{
		{Name: "*",
			LocalForwards:   []string{"9000 127.0.0.1:9000", "9001 127.0.0.1:9001"},
			RemoteForwards:  []string{"8080 localhost:80"},
			DynamicForwards: []string{"1080"},
			Extra:           map[string]string{"SendEnv": "LANG LC_*", "ServerAliveInterval": "30"}},
		{Name: "jump",
			LocalForwards:   []string{"9001 127.0.0.1:9001", "9002 127.0.0.1:9002"},
			RemoteForwards:  []string{"8080 localhost:80", "8081 localhost:81"},
			DynamicForwards: []string{"1080", "1081"},
			Extra:           map[string]string{"SendEnv": "LC_* TERM", "ServerAliveInterval": "60"}},
		{Name: "ju*", LocalForwards: []string{"9000 127.0.0.1:9000"}},
	}
	got, err := EffectiveConfig(hosts, "jump")
	if err != nil {
		t.Fatal(err)
	}
	eq := func(what string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s = %v, want %v", what, got, want)
			}
		}
	}
	eq("LocalForwards", got.LocalForwards, []string{"9000 127.0.0.1:9000", "9001 127.0.0.1:9001", "9002 127.0.0.1:9002"})
	eq("RemoteForwards", got.RemoteForwards, []string{"8080 localhost:80", "8081 localhost:81"})
	eq("DynamicForwards", got.DynamicForwards, []string{"1080", "1081"})
	if got.Extra["SendEnv"] != "LANG LC_* TERM" {
		t.Errorf("SendEnv = %q, want accumulated %q", got.Extra["SendEnv"], "LANG LC_* TERM")
	}
	if got.Extra["ServerAliveInterval"] != "30" {
		t.Errorf("ServerAliveInterval = %q, want first-wins 30", got.Extra["ServerAliveInterval"])
	}
}

func TestEffectiveConfig_IdentityFileFirstWins(t *testing.T) {
	// Documented model limitation: ssh accumulates IdentityFile across
	// blocks, the single-valued field keeps the first.
	hosts := []Host{
		{Name: "h", IdentityFile: "/k/one"},
		{Name: "*", IdentityFile: "/k/two"},
	}
	got, _ := EffectiveConfig(hosts, "h")
	if got.IdentityFile != "/k/one" {
		t.Errorf("IdentityFile = %q, want /k/one", got.IdentityFile)
	}
	if m := MatchingHosts(hosts, "h"); len(m) != 2 {
		t.Errorf("MatchingHosts = %d, want 2", len(m))
	}
}
