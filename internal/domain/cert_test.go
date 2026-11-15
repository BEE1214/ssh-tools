package domain

import (
	"strings"
	"testing"
	"time"
)

func certText(keyID, valid string) string {
	return `/example/id-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:abcdef
        Signing CA: ED25519 SHA256:fedcba (using ssh-ed25519)
        Key ID: ` + keyID + `
        Serial: 7
        Valid: ` + valid + `
        Principals:
                alice
                bob
        Critical Options: (none)
        Extensions:
                permit-pty
`
}

func TestParseCertInfo_ValidityForms(t *testing.T) {
	ts1 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	ts2 := time.Date(2030, 1, 1, 12, 30, 5, 0, time.UTC)
	tests := []struct {
		name, valid   string
		after, before time.Time
		validity      string
		expires       string
		neverExpires  bool
	}{
		{"forever", "forever", time.Time{}, time.Time{}, "forever", "never", true},
		{"from-to", "from 2020-01-01T00:00:00 to 2030-01-01T12:30:05", ts1, ts2,
			"2020-01-01 00:00:00 to 2030-01-01 12:30:05", "2030-01-01 12:30:05", false},
		{"after", "after 2020-01-01T00:00:00", ts1, time.Time{}, "after 2020-01-01 00:00:00", "never", true},
		{"before", "before 2030-01-01T12:30:05", time.Time{}, ts2, "before 2030-01-01 12:30:05", "2030-01-01 12:30:05", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseCertInfoIn("/example/id-cert.pub", certText(`"id"`, tt.valid), time.UTC) // fixed zone: timestamps are UTC here
			if err != nil {
				t.Fatal(err)
			}
			if !c.ValidAfter.Equal(tt.after) || !c.ValidBefore.Equal(tt.before) {
				t.Errorf("after/before = %v / %v, want %v / %v", c.ValidAfter, c.ValidBefore, tt.after, tt.before)
			}
			if got := c.Validity(); got != tt.validity {
				t.Errorf("Validity() = %q, want %q", got, tt.validity)
			}
			if got := c.Expires(); got != tt.expires {
				t.Errorf("Expires() = %q, want %q", got, tt.expires)
			}
			if c.NeverExpires() != tt.neverExpires {
				t.Errorf("NeverExpires() = %v", c.NeverExpires())
			}
			if tt.neverExpires && c.IsExpired() {
				t.Error("certificate without expiry reported as expired")
			}
			if wantExpired := !tt.neverExpires && time.Now().After(tt.before); c.IsExpired() != wantExpired {
				t.Errorf("IsExpired() = %v, want %v", c.IsExpired(), wantExpired)
			}
			if c.Serial != 7 || c.Identity != "id" || len(c.Principals) != 2 {
				t.Errorf("other fields wrong: %+v", c)
			}
			if strings.Contains(c.Validity(), "0001-01-01") || strings.Contains(c.Expires(), "0001-01-01") {
				t.Error("zero time leaked into display text")
			}
		})
	}
}

func TestParseCertInfo_ValidityErrors(t *testing.T) {
	for _, valid := range []string{"", "someday", "from 2020-01-01T00:00:00", "from garbage to garbage", "after garbage", "before "} {
		if _, err := ParseCertInfo("/example/id-cert.pub", certText(`"id"`, valid)); err == nil {
			t.Errorf("Valid: %q parsed without error", valid)
		}
	}
	if _, err := ParseCertInfo("/example/id-cert.pub", "Type: x\n"); err == nil {
		t.Error("output without a Valid line parsed without error")
	}
}

func TestParseCertInfo_KeyID(t *testing.T) {
	tests := []struct{ raw, want string }{
		{`"x"`, "x"},
		{`"my id"`, "my id"},
		{`"my "quoted" id"`, `my "quoted" id`},
		{`""`, ""},
		{`"`, `"`},
		{`bare`, "bare"},
	}
	for _, tt := range tests {
		c, err := ParseCertInfo("/example/id-cert.pub", certText(tt.raw, "forever"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Identity != tt.want {
			t.Errorf("Key ID %s -> %q, want %q", tt.raw, c.Identity, tt.want)
		}
	}
}
