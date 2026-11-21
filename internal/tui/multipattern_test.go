package tui

// P7 clause M3 (PLAN-p7.md): `e`, `d` and `D` on the row of a multi-pattern Host
// line show the app layer's ReadOnlyReason as the toast, and nothing is opened.
// Hosts with a single pattern are unaffected.

import "testing"

const mpTUIMain = "Include @M@\nInclude @D@/extra.conf\n\nHost mm-1 mm-2\n  HostName 10.0.2.1\n"

const mpTUIManaged = `# Managed by sshm. Hosts in this file are edited by sshm.
# Lines you add by hand are kept.

Host web-1
  HostName 10.0.0.1
  User alice

Host db-1 db-2
  HostName 10.0.2.20

Host dc-1 dc-2 # pair
  HostName 10.0.2.21
`

const hasSeveral = " has several patterns, which sshm cannot edit"

// M3: the toast of e/d/D on a multi-pattern row is the Snapshot's ReadOnlyReason,
// whichever file the line is in (managed file, main file, included file).
func TestMultiPatternTUI_EditKeysShowTheReason(t *testing.T) {
	// "dc-1 dc-2" is the line `Host dc-1 dc-2 # pair`: the name has the comment
	// stripped (N1, PLAN-p7.md item 13).
	for _, name := range []string{"db-1 db-2", "dc-1 dc-2", "mm-1 mm-2", "inc-multi-1 inc-multi-2"} {
		t.Run(name, func(t *testing.T) {
			e := tmNewEnv(t, tmEnvMain(name), tmEnvManaged())
			if name == "inc-multi-1 inc-multi-2" {
				tmWrite(t, e.extra, "Host "+name+"\n  HostName 10.0.3.1\n", 0o600)
			}
			m := tmModel(e)
			file := map[string]string{"db-1 db-2": e.managed, "dc-1 dc-2": e.managed, "mm-1 mm-2": e.main, "inc-multi-1 inc-multi-2": e.extra}[name]
			reason := `"Host ` + name + `" in ` + file + hasSeveral
			snap, err := e.a.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, h := range snap.Hosts {
				if h.Name == name {
					found = true
					if h.ReadOnlyReason != reason {
						t.Errorf("Snapshot reason for %q = %q, want %q", name, h.ReadOnlyReason, reason)
					}
				}
			}
			if !found {
				t.Fatalf("Snapshot has no entry %q", name)
			}
			m = onHost(m, name)
			if curKey(m) == "" {
				t.Fatalf("no row for %q", name)
			}
			for _, key := range []string{"e", "d", "D"} {
				m, _ = press(m, key)
				if m.mode != modeList {
					t.Fatalf("key %q left list mode (mode=%v)", key, m.mode)
				}
				if !m.toastErr || m.toast != reason {
					t.Errorf("key %q: toast %q (error=%v), want the reason %q", key, m.toast, m.toastErr, reason)
				}
				m.toast = ""
			}
		})
	}
}

// Single-pattern hosts keep working: `e` opens the editor on web-1.
func TestMultiPatternTUI_SinglePatternHostStillEdits(t *testing.T) {
	e := tmNewEnv(t, tmEnvMain("mm-1 mm-2"), tmEnvManaged())
	m := onHost(tmModel(e), "web-1")
	m, _ = press(m, "e")
	if m.mode == modeList || m.toastErr {
		t.Errorf("e on web-1: mode %v, toast %q (error=%v), want the editor", m.mode, m.toast, m.toastErr)
	}
}

func tmEnvMain(multiName string) string {
	body := mpTUIMain
	if multiName == "inc-multi-1 inc-multi-2" {
		return "Include @M@\nInclude @D@/extra.conf\n"
	}
	return body
}

func tmEnvManaged() string { return mpTUIManaged }
