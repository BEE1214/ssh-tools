package domain

import "testing"

// TestParseForwardSpec_RejectsUnsafeHosts: targetHost and bindAddr must not
// carry whitespace, control characters, a leading '-', or characters outside
// the conservative set — otherwise a spec can inject extra ssh_config lines
// or ssh options.
func TestParseForwardSpec_RejectsUnsafeHosts(t *testing.T) {
	tests := []struct {
		name string
		kind ForwardKind
		spec string
	}{
		{"newline injection", ForwardLocal, "8080:a\nProxyCommand evil:80"},
		{"crlf injection", ForwardLocal, "8080:a\r\nProxyCommand evil:80"},
		{"space in target host", ForwardLocal, "8080:a b:80"},
		{"tab in target host", ForwardLocal, "8080:a\tb:80"},
		{"control char in target host", ForwardLocal, "8080:a\x07b:80"},
		{"leading dash target host", ForwardLocal, "8080:-oProxyCommand:80"},
		{"equals in target host", ForwardLocal, "8080:a=b:80"},
		{"quote in target host", ForwardRemote, "8080:a\"b:80"},
		{"shell meta in target host", ForwardRemote, "8080:a;rm:80"},
		{"newline in bind addr", ForwardLocal, "127.0.0.1\nProxyCommand evil:8080:host:80"},
		{"space in bind addr", ForwardLocal, "10.0.0.1 x:8080:host:80"},
		{"leading dash bind addr", ForwardLocal, "-oX:8080:host:80"},
		{"newline in dynamic bind addr", ForwardDynamic, "127.0.0.1\nProxyCommand evil:1080"},
		{"leading dash dynamic bind addr", ForwardDynamic, "-oX:1080"},
		{"star outside bind addr", ForwardLocal, "8080:*:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := ParseForwardSpec(tt.kind, tt.spec); err == nil {
				t.Errorf("ParseForwardSpec(%q) = %q, want error", tt.spec, got)
			}
		})
	}
}

// TestParseForwardSpec_AcceptsSafeHosts guards against over-rejecting.
func TestParseForwardSpec_AcceptsSafeHosts(t *testing.T) {
	tests := []struct {
		kind ForwardKind
		spec string
		want string
	}{
		{ForwardLocal, "8080:db-1.internal_x:5432", "8080 db-1.internal_x:5432"},
		{ForwardLocal, "127.0.0.1:8080:10.0.0.5:80", "127.0.0.1:8080 10.0.0.5:80"},
		{ForwardLocal, "*:8080:host:80", "*:8080 host:80"},
		{ForwardDynamic, "127.0.0.1:1080", "127.0.0.1:1080"},
	}
	for _, tt := range tests {
		got, err := ParseForwardSpec(tt.kind, tt.spec)
		if err != nil {
			t.Errorf("ParseForwardSpec(%q): %v", tt.spec, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseForwardSpec(%q) = %q, want %q", tt.spec, got, tt.want)
		}
	}
}
