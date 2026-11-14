package domain

import "testing"

// TestDefaultIdentityFile pins the default identity placeholder used for
// ad-hoc connections and new hosts.
func TestDefaultIdentityFile(t *testing.T) {
	if DefaultIdentityFile != "~/.ssh/id_ed25519" {
		t.Errorf("DefaultIdentityFile = %q, want ~/.ssh/id_ed25519", DefaultIdentityFile)
	}
}
