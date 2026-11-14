package app

import "testing"

// TestAddForwardRejectsInjection: a forward spec carrying a line break must
// be rejected and must not add any directive to the config.
func TestAddForwardRejectsInjection(t *testing.T) {
	a := newTestApp(t, groupFixture)
	before := configAfter(t, a)

	err := a.AddForward("web-1", 0, []string{"8080:a\nProxyCommand evil:80"})
	if err == nil {
		t.Fatal("AddForward accepted an injection spec")
	}
	if got := configAfter(t, a); got != before {
		t.Errorf("config changed after rejected spec:\n%s", got)
	}
}
