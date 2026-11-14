package domain

import "testing"

func TestParseForwardSpec_Local3Part(t *testing.T) {
	got, err := ParseForwardSpec(ForwardLocal, "10100:192.168.1.100:80")
	if err != nil {
		t.Fatal(err)
	}
	if want := "10100 192.168.1.100:80"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseForwardSpec_Local4PartBindAddr(t *testing.T) {
	got, err := ParseForwardSpec(ForwardLocal, "127.0.0.1:10100:192.168.1.100:80")
	if err != nil {
		t.Fatal(err)
	}
	if want := "127.0.0.1:10100 192.168.1.100:80"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseForwardSpec_Remote(t *testing.T) {
	got, err := ParseForwardSpec(ForwardRemote, "8080:localhost:80")
	if err != nil {
		t.Fatal(err)
	}
	if want := "8080 localhost:80"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseForwardSpec_Dynamic(t *testing.T) {
	got, err := ParseForwardSpec(ForwardDynamic, "1080")
	if err != nil {
		t.Fatal(err)
	}
	if want := "1080"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseForwardSpec_DynamicBindAddr(t *testing.T) {
	got, err := ParseForwardSpec(ForwardDynamic, "0.0.0.0:1080")
	if err != nil {
		t.Fatal(err)
	}
	if want := "0.0.0.0:1080"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseForwardSpec_Invalid(t *testing.T) {
	tests := []struct {
		name string
		kind ForwardKind
		spec string
	}{
		{"too few colons local", ForwardLocal, "10100"},
		{"too few colons local2", ForwardLocal, "10100:192.168.1.100"},
		{"empty target host", ForwardLocal, "10100::80"},
		{"non-numeric listen port", ForwardLocal, "abc:192.168.1.100:80"},
		{"listen port out of range", ForwardLocal, "70000:192.168.1.100:80"},
		{"non-numeric target port", ForwardRemote, "8080:localhost:abc"},
		{"non-numeric dynamic port", ForwardDynamic, "notaport"},
		{"dynamic port out of range", ForwardDynamic, "0"},
		{"ipv6 bracket local", ForwardLocal, "[::1]:10100:192.168.1.100:80"},
		{"ipv6 bracket dynamic", ForwardDynamic, "[::1]:1080"},
		{"empty spec", ForwardLocal, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseForwardSpec(tt.kind, tt.spec); err == nil {
				t.Errorf("ParseForwardSpec(%v, %q) = nil error, want error", tt.kind, tt.spec)
			}
		})
	}
}

func TestValidateForwardEntry(t *testing.T) {
	tests := []struct {
		name    string
		kind    ForwardKind
		entry   string
		wantErr bool
	}{
		{"valid local", ForwardLocal, "10100 192.168.1.100:80", false},
		{"valid local with bind addr", ForwardLocal, "127.0.0.1:10100 192.168.1.100:80", false},
		{"valid remote", ForwardRemote, "8080 localhost:80", false},
		{"valid dynamic", ForwardDynamic, "1080", false},
		{"valid dynamic with bind addr", ForwardDynamic, "0.0.0.0:1080", false},
		{"local missing target colon", ForwardLocal, "10100 192.168.1.100", true},
		{"local bad port", ForwardLocal, "abc 192.168.1.100:80", true},
		{"local too many tokens", ForwardLocal, "10100 192.168.1.100:80 extra", true},
		{"local one token", ForwardLocal, "10100", true},
		{"dynamic two tokens", ForwardDynamic, "1080 extra", true},
		{"dynamic bad port", ForwardDynamic, "notanumber", true},
		{"dynamic port out of range", ForwardDynamic, "99999", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateForwardEntry(tt.kind, tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateForwardEntry(%v, %q) err = %v, wantErr %v", tt.kind, tt.entry, err, tt.wantErr)
			}
		})
	}
}

func TestListenPort(t *testing.T) {
	tests := []struct {
		kind  ForwardKind
		entry string
		want  string
	}{
		{ForwardLocal, "10100 192.168.1.100:80", "10100"},
		{ForwardLocal, "127.0.0.1:10100 192.168.1.100:80", "10100"},
		{ForwardDynamic, "1080", "1080"},
		{ForwardDynamic, "0.0.0.0:1080", "1080"},
	}
	for _, tt := range tests {
		got := ListenPort(tt.kind, tt.entry)
		if got != tt.want {
			t.Errorf("ListenPort(%v, %q) = %q, want %q", tt.kind, tt.entry, got, tt.want)
		}
	}
}
