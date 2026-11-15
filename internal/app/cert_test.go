package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// signCert signs a fresh user key with a throwaway CA in dir using real
// ssh-keygen. validity == "" omits -V; id is the key ID.
func signCert(t *testing.T, dir, name, id, validity string) string {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
		}
	}
	ca := filepath.Join(dir, "ca")
	if !fileExists(ca) {
		run("-q", "-t", "ed25519", "-N", "", "-f", ca)
	}
	key := filepath.Join(dir, name)
	run("-q", "-t", "ed25519", "-N", "", "-f", key)
	args := []string{"-q", "-s", ca, "-I", id, "-n", "placeholder-user"}
	if validity != "" {
		args = append(args, "-V", validity)
	}
	run(append(args, key+".pub")...)
	return key + "-cert.pub"
}

// ssh-keygen -L prints validity times in the LOCAL time of the process, with no
// zone. Run it under several TZ values (the child process honours TZ even
// though Go's time.Local is fixed at startup) and parse with the matching zone:
// a `-V +1d` cert must be unexpired and expire ~24h from now in every zone.
func TestInspectCert_ExpiryIndependentOfZone(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
	path := signCert(t, t.TempDir(), "zone", "id-zone", "+1d")
	for _, tz := range []string{"UTC", "Etc/GMT-5", "Etc/GMT+8", "Pacific/Kiritimati", "Asia/Kolkata"} {
		t.Run(tz, func(t *testing.T) {
			loc, err := time.LoadLocation(tz)
			if err != nil {
				t.Skipf("zone %s unavailable: %v", tz, err)
			}
			cmd := exec.Command("ssh-keygen", "-L", "-f", path)
			cmd.Env = append(os.Environ(), "TZ="+tz)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("ssh-keygen -L: %v\n%s", err, out)
			}
			now := time.Now()
			c, err := domain.ParseCertInfoIn(path, string(out), loc)
			if err != nil {
				t.Fatalf("parse: %v\n%s", err, out)
			}
			if c.IsExpired() {
				t.Errorf("fresh +1d cert reported expired in %s: %s", tz, out)
			}
			if d := c.ValidBefore.Sub(now); d <= 23*time.Hour || d >= 25*time.Hour {
				t.Errorf("expires in %v in %s, want within (23h, 25h)\n%s", d, tz, out)
			}
		})
	}
}

func TestInspectCert_RealSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
	dir := t.TempDir()
	a := NewAppWithPath(filepath.Join(dir, "config"))
	now := time.Now()

	tests := []struct {
		name, validity string
		check          func(t *testing.T, c domain.Certificate)
	}{
		{"relative-1d", "+1d", func(t *testing.T, c domain.Certificate) {
			if c.NeverExpires() || c.IsExpired() {
				t.Errorf("expiry wrong: %+v", c)
			}
			if d := c.ValidBefore.Sub(now); d <= 23*time.Hour || d >= 25*time.Hour {
				// Tight on purpose: times are local, so a zone mix-up shows as
				// a multi-hour error on any non-UTC machine.
				t.Errorf("expires in %v, want within (23h, 25h)", d)
			}
			if c.ValidAfter.IsZero() {
				t.Error("ValidAfter unset for a timed cert")
			}
		}},
		{"forever-no-V", "", func(t *testing.T, c domain.Certificate) {
			if !c.NeverExpires() || c.IsExpired() || !c.ValidAfter.IsZero() || c.Validity() != "forever" || c.Expires() != "never" {
				t.Errorf("forever cert wrong: %+v validity=%q", c, c.Validity())
			}
		}},
		{"absolute-window", "20200101:20300101", func(t *testing.T, c domain.Certificate) {
			if c.ValidAfter.Year() != 2020 || c.ValidBefore.Year() != 2030 || c.IsExpired() {
				t.Errorf("window wrong: %v .. %v", c.ValidAfter, c.ValidBefore)
			}
		}},
		{"expired-window", "20200101:20210101", func(t *testing.T, c domain.Certificate) {
			if !c.IsExpired() {
				t.Errorf("2020-2021 cert not expired: %+v", c)
			}
		}},
		{"now-to-forever", "+1d:forever", func(t *testing.T, c domain.Certificate) {
			if !c.NeverExpires() || c.ValidAfter.IsZero() || !strings.HasPrefix(c.Validity(), "after ") {
				t.Errorf("after-only cert wrong: %+v validity=%q", c, c.Validity())
			}
		}},
		{"always-to-1d", "always:+1d", func(t *testing.T, c domain.Certificate) {
			if c.NeverExpires() || !c.ValidAfter.IsZero() || !strings.HasPrefix(c.Validity(), "before ") {
				t.Errorf("before-only cert wrong: %+v validity=%q", c, c.Validity())
			}
		}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := signCert(t, dir, "k"+string(rune('a'+i)), "id-"+tt.name, tt.validity)
			c, err := a.InspectCert(path)
			if err != nil {
				out, _ := exec.Command("ssh-keygen", "-L", "-f", path).CombinedOutput()
				t.Fatalf("InspectCert: %v\nssh-keygen -L:\n%s", err, out)
			}
			if c.Identity != "id-"+tt.name {
				t.Errorf("Identity = %q", c.Identity)
			}
			tt.check(t, c)
			if strings.Contains(c.Validity(), "0001-01-01") || strings.Contains(c.Expires(), "0001-01-01") {
				t.Errorf("zero time leaked into display: %q / %q", c.Validity(), c.Expires())
			}
		})
	}
}

func TestInspectCert_KeyIDWithQuotesAndSpaces(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
	dir := t.TempDir()
	a := NewAppWithPath(filepath.Join(dir, "config"))
	for i, id := range []string{"my id", `say "hi" now`, "x"} {
		path := signCert(t, dir, "q"+string(rune('a'+i)), id, "+1d")
		c, err := a.InspectCert(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.Identity != id {
			t.Errorf("Identity = %q, want %q", c.Identity, id)
		}
	}
}
