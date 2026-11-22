package cli

// P7 clause X3 (PLAN-p7.md): layering unchanged. internal/cli imports only
// internal/app and internal/domain among the internal packages; internal/domain
// imports no internal package. (internal/tui has its own check in
// internal/tui/managed_test.go.) Characterization, green now.

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

const modulePrefix = "github.com/adamdvorsky/ssh-tools/internal/"

// internalImports returns, per non-test file of dir, the internal packages it imports.
func internalImports(t *testing.T, dir string) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, imp := range af.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); strings.HasPrefix(p, modulePrefix) {
				out[filepath.Base(f)] = append(out[filepath.Base(f)], strings.TrimPrefix(p, modulePrefix))
			}
		}
	}
	if n == 0 {
		t.Fatalf("no source files in %s: the check would be vacuous", dir)
	}
	return out
}

func TestLayering_CLIImportsOnlyAppAndDomain(t *testing.T) {
	seenApp := false
	for f, imps := range internalImports(t, ".") {
		for _, p := range imps {
			switch p {
			case "app":
				seenApp = true
			case "domain":
			case "tui":
				// PLAN-p7.md X3 says "only app and domain", but cli/tui.go has always
				// started the TUI (see the report, ambiguity); only that file may.
				if f != "tui.go" {
					t.Errorf("internal/cli/%s imports internal/tui; only tui.go starts it", f)
				}
			default:
				t.Errorf("internal/cli/%s imports internal/%s; only internal/app, internal/domain (and tui from tui.go) are allowed", f, p)
			}
		}
	}
	if !seenApp {
		t.Error("no file of internal/cli imports internal/app: the check does not see the imports")
	}
}

func TestLayering_DomainImportsNoInternalPackage(t *testing.T) {
	for f, imps := range internalImports(t, "../domain") {
		t.Errorf("internal/domain/%s imports %v; domain must not import internal packages", f, imps)
	}
}
