package app

import (
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// TestMutationsOnDisabledHostRefused: edit-style operations on a host in a
// disabled group must return a clear error and leave the config untouched
// (they used to save successfully while silently dropping the change).
func TestMutationsOnDisabledHostRefused(t *testing.T) {
	a := newTestApp(t, groupFixture)
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	before := configAfter(t, a)

	cases := []struct {
		name string
		call func() error
	}{
		{"EditHost", func() error { return a.EditHost("deploy-acq", map[string]string{"user": "other"}) }},
		{"DuplicateHost", func() error { return a.DuplicateHost("deploy-acq", "deploy-copy") }},
		{"ClearCertificateFile", func() error { return a.ClearCertificateFile("deploy-acq") }},
		{"AddForward", func() error {
			return a.AddForward("deploy-acq", domain.ForwardLocal, []string{"8080:localhost:80"})
		}},
		{"ClearForwards", func() error { return a.ClearForwards("deploy-acq") }},
	}
	for _, tc := range cases {
		wantDisabledErr(t, tc.name, tc.call())
		if got := configAfter(t, a); got != before {
			t.Errorf("%s modified the config:\nbefore:\n%s\nafter:\n%s", tc.name, before, got)
		}
	}
}
