package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// TestBlockLinesRefusesLineBreaks: no host value may contain CR/LF, otherwise
// a value could inject extra config lines.
func TestBlockLinesRefusesLineBreaks(t *testing.T) {
	inj := "a\nProxyCommand evil"
	tests := []struct {
		name string
		h    domain.Host
	}{
		{"hostname", domain.Host{Name: "h", HostName: inj}},
		{"user", domain.Host{Name: "h", User: "u\r\nX y"}},
		{"name", domain.Host{Name: "h\nHost evil"}},
		{"identity", domain.Host{Name: "h", IdentityFile: inj}},
		{"group", domain.Host{Name: "h", Group: "g\nProxyCommand evil"}},
		{"local forward", domain.Host{Name: "h", LocalForwards: []string{"8080 " + inj + ":80"}}},
		{"remote forward", domain.Host{Name: "h", RemoteForwards: []string{inj}}},
		{"dynamic forward", domain.Host{Name: "h", DynamicForwards: []string{inj}}},
		{"extra value", domain.Host{Name: "h", Extra: map[string]string{"Foo": inj}}},
		{"extra key", domain.Host{Name: "h", Extra: map[string]string{inj: "x"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := BlockLines(tt.h)
			if err == nil {
				t.Fatalf("BlockLines succeeded, output:\n%s", strings.Join(out, "\n"))
			}
			if !errors.Is(err, ErrBadValue) {
				t.Errorf("error %v does not wrap ErrBadValue", err)
			}
			// A name with a line break is already refused as a name.
			if tt.name != "name" && !strings.Contains(err.Error(), "line break") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestBlockLinesAllowsNormalValues: the check does not reject ordinary hosts.
func TestBlockLinesAllowsNormalValues(t *testing.T) {
	h := domain.Host{Name: "web-1", HostName: "10.0.0.1", User: "admin",
		LocalForwards: []string{"8080 localhost:80"}, Extra: map[string]string{"ServerAliveInterval": "30"}}
	if _, err := BlockLines(h); err != nil {
		t.Fatalf("BlockLines: %v", err)
	}
}
