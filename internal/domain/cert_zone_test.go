package domain

import (
	"testing"
	"time"
)

// ssh-keygen prints validity in LOCAL time with no zone: the same literal text
// is a different instant under a different zone, offset by exactly the zone
// difference.
func TestParseCertInfo_ZonelessTimeUsesGivenZone(t *testing.T) {
	const valid = "from 2024-03-01T08:00:00 to 2024-03-02T09:30:00"
	plus530 := time.FixedZone("T", 5*3600+1800)
	minus8 := time.FixedZone("W", -8*3600)

	parse := func(loc *time.Location) Certificate {
		t.Helper()
		c, err := ParseCertInfoIn("/example/id-cert.pub", certText(`"id"`, valid), loc)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	utc, east, west := parse(time.UTC), parse(plus530), parse(minus8)

	if want := time.Date(2024, 3, 1, 8, 0, 0, 0, time.UTC); !utc.ValidAfter.Equal(want) {
		t.Errorf("UTC ValidAfter = %v, want %v", utc.ValidAfter, want)
	}
	// 08:00 in UTC+5:30 happened 5h30 BEFORE 08:00 UTC.
	if d := utc.ValidAfter.Sub(east.ValidAfter); d != 5*time.Hour+30*time.Minute {
		t.Errorf("UTC vs +05:30 ValidAfter differ by %v, want 5h30m", d)
	}
	if d := utc.ValidBefore.Sub(east.ValidBefore); d != 5*time.Hour+30*time.Minute {
		t.Errorf("UTC vs +05:30 ValidBefore differ by %v, want 5h30m", d)
	}
	if d := west.ValidBefore.Sub(utc.ValidBefore); d != 8*time.Hour {
		t.Errorf("-08:00 vs UTC ValidBefore differ by %v, want 8h", d)
	}
	// The wall-clock text shown to the user is what ssh-keygen printed.
	if got := east.Expires(); got != "2024-03-02 09:30:00" {
		t.Errorf("Expires() = %q", got)
	}
	// A nil location falls back to local rather than panicking.
	if _, err := ParseCertInfoIn("/example/id-cert.pub", certText(`"id"`, valid), nil); err != nil {
		t.Errorf("nil location: %v", err)
	}
}

func TestParseCertInfo_ExplicitZoneIsKept(t *testing.T) {
	loc := time.FixedZone("T", 5*3600+1800)
	c, err := ParseCertInfoIn("/example/id-cert.pub",
		certText(`"id"`, "from 2024-03-01T08:00:00Z to 2024-03-02T09:30:00+0200"), loc)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2024, 3, 1, 8, 0, 0, 0, time.UTC); !c.ValidAfter.Equal(want) {
		t.Errorf("Z timestamp = %v, want %v", c.ValidAfter, want)
	}
	if want := time.Date(2024, 3, 2, 7, 30, 0, 0, time.UTC); !c.ValidBefore.Equal(want) {
		t.Errorf("+0200 timestamp = %v, want %v", c.ValidBefore, want)
	}
}

// In a +05:30 zone, a wall-clock expiry one hour ahead of "now" in that zone
// must be unexpired and one hour behind must be expired. Read as UTC the first
// would be 4h30 in the past (wrongly expired).
func TestIsExpired_NonUTCZone(t *testing.T) {
	loc := time.FixedZone("T", 5*3600+1800)
	wall := func(d time.Duration) string {
		return "before " + time.Now().In(loc).Add(d).Format("2006-01-02T15:04:05")
	}
	fut, err := ParseCertInfoIn("/e", certText(`"id"`, wall(time.Hour)), loc)
	if err != nil {
		t.Fatal(err)
	}
	past, err := ParseCertInfoIn("/e", certText(`"id"`, wall(-time.Hour)), loc)
	if err != nil {
		t.Fatal(err)
	}
	if fut.IsExpired() {
		t.Error("expiry 1h ahead in the cert's zone reported expired")
	}
	if !past.IsExpired() {
		t.Error("expiry 1h behind in the cert's zone not reported expired")
	}
	if d := time.Until(fut.ValidBefore); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("expires in %v, want ~1h", d)
	}
}
