package config

// Parse records every Include directive of a file in ConfigFile.Includes:
// 1-based Line, the Patterns, and Conditional (false above the first
// Host/Match and directly below a bare `Host *`; true below a `Host web-*`
// line). Lines inside disabled-group markers are not directives. Where the
// claim is about ssh (what "conditional" means) the oracle is real
// `ssh -F <file> -G`.

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parseIncludes(t *testing.T, text string) []IncludeDirective {
	t.Helper()
	cfg, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, text)
	}
	return cfg.Includes
}

func TestParseRecordsIncludes(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		want []IncludeDirective
	}{
		{
			name: "include on line 1 then host blocks",
			text: "Include config.d/sshm.conf\n\nHost a\n  HostName 10.0.0.1\n\nHost b\n  HostName 10.0.0.2\n",
			want: []IncludeDirective{{Line: 1, Patterns: []string{"config.d/sshm.conf"}}},
		},
		{
			name: "two includes, line numbers and patterns",
			text: "# top\nInclude one.conf two.conf\n\nHost *\n  Include three.conf\n",
			want: []IncludeDirective{
				{Line: 2, Patterns: []string{"one.conf", "two.conf"}},
				{Line: 5, Patterns: []string{"three.conf"}},
			},
		},
		{
			name: "include in a disabled region is not recorded",
			text: "Include real.conf\n\n# sshm disabled group=prod start\n# Include ghost.conf\nInclude ghost2.conf\n# sshm disabled group=prod end\n",
			want: []IncludeDirective{{Line: 1, Patterns: []string{"real.conf"}}},
		},
		{
			name: "include in a plain comment is not recorded",
			text: "# Include nope.conf\nHost a\n  HostName h\n",
			want: nil,
		},
		{
			name: "include below a conditional Host line",
			text: "Host web-*\n  Include inc.conf\n",
			want: []IncludeDirective{{Line: 2, Patterns: []string{"inc.conf"}, Conditional: true}},
		},
		{
			name: "include directly below a bare Host * is unconditional",
			text: "Host *\nInclude inc.conf\n",
			want: []IncludeDirective{{Line: 2, Patterns: []string{"inc.conf"}}},
		},
		{
			name: "the nearest Host line counts",
			text: "Host web-*\n  User u\nHost *\nInclude star.conf\nHost db-*\nInclude db.conf\n",
			want: []IncludeDirective{
				{Line: 4, Patterns: []string{"star.conf"}},
				{Line: 6, Patterns: []string{"db.conf"}, Conditional: true},
			},
		},
		{
			name: "lower case keyword",
			text: "include lower.conf\nHost a\n",
			want: []IncludeDirective{{Line: 1, Patterns: []string{"lower.conf"}}},
		},
		{
			name: "equals spelling",
			text: "Host a\n  HostName h\nHost web-*\nInclude=eq.conf\nInclude = eq2.conf\n",
			want: []IncludeDirective{
				{Line: 4, Patterns: []string{"eq.conf"}, Conditional: true},
				{Line: 5, Patterns: []string{"eq2.conf"}, Conditional: true},
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := parseIncludes(t, c.text)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Includes = %+v, want %+v\nfile:\n%s", got, c.want, c.text)
			}
		})
	}
}

// What "Conditional" means for ssh: an Include below `Host web-*` is applied
// only to hosts that match web-*, one above the first Host line (and one
// directly below `Host *`) to every host.
func TestParseIncludeConditionalAgreesWithSSH(t *testing.T) {
	needSSH(t)
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "User incuser\n")

	for _, c := range []struct {
		name        string
		text        string
		conditional bool
		web, other  bool // does ssh apply the included file to web-1 / other?
	}{
		{"below Host web-*", "Host web-*\n  Include " + inc + "\n", true, true, false},
		{"above the first Host", "Include " + inc + "\n\nHost web-*\n  Port 2200\n", false, true, true},
		{"below Host *", "Host *\n  Include " + inc + "\n", false, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfgPath := write(t, filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_")+".cfg"), c.text)
			inc := parseIncludes(t, c.text)
			if len(inc) != 1 || inc[0].Conditional != c.conditional {
				t.Fatalf("Includes = %+v, want one directive with Conditional=%v", inc, c.conditional)
			}
			if got := sshUser(t, cfgPath, "web-1") == "incuser"; got != c.web {
				t.Errorf("ssh applies the include to web-1 = %v, want %v", got, c.web)
			}
			if got := sshUser(t, cfgPath, "other") == "incuser"; got != c.other {
				t.Errorf("ssh applies the include to other = %v, want %v", got, c.other)
			}
		})
	}
}
