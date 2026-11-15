package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

// fixture is in the config writer's canonical form (2-space indent, canonical
// option order, no blank line after the leading comments, DevPod options in
// writer order) so a write cycle is the identity on untouched hosts. The
// writer is a full re-serializer, not a surgical editor: configs that are
// NOT in this form get normalized on the first write. It exercises the interesting block kinds:
// leading comments, a Host * defaults block, a DevPod block, an ungrouped
// host and a group that the tests disable. Placeholders only.
const fixture = `# Example ssh config
# Hand-written notes live up here.
Host *
  StrictHostKeyChecking accept-new
  ServerAliveInterval 60

Host web-1
  HostName 10.0.0.1
  User admin
  IdentityFile ~/.ssh/id_example

Host web-2
  HostName 10.0.0.2
  User admin

# DevPod Start demo.devpod
Host demo.devpod
  User root
  ProxyCommand "/usr/bin/devpod-cli" ssh --stdio --context default --user root demo
  ForwardAgent yes
  StrictHostKeyChecking no
  LogLevel error
  HostKeyAlgorithms rsa-sha2-256
# DevPod End demo.devpod

Host deploy-acq
  HostName example.com
  User deploy
  IdentityFile ~/.ssh/id_deploy

Host deploy-eu
  HostName 10.0.0.20
  User deploy

Host solo
  HostName 10.0.0.9
  Port 2222
`

// newTestModel writes cfg to a temp file and returns a Model over it.
func newTestModel(t *testing.T, cfg string) (Model, *app.App, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	a := app.NewAppWithPath(path)
	m := New(a)
	m.editable = true
	return m, a, path
}

// withDisabledDeploy returns a model over fixture with group "deploy"
// disabled via the app layer.
func withDisabledDeploy(t *testing.T) (Model, *app.App, string) {
	t.Helper()
	_, a, path := newTestModel(t, fixture)
	if err := a.DisableGroup("deploy"); err != nil {
		t.Fatal(err)
	}
	m := New(a)
	m.editable = true
	return m, a, path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keyMsg builds the KeyPressMsg a terminal would produce for a key name
// such as "j", "D", "enter", "shift+tab" or "ctrl+s".
func keyMsg(s string) tea.KeyPressMsg {
	named := map[string]rune{
		"enter": tea.KeyEnter, "esc": tea.KeyEscape, "tab": tea.KeyTab,
		"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
	}
	if r, ok := named[s]; ok {
		return tea.KeyPressMsg{Code: r}
	}
	if s == "shift+tab" {
		return tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	}
	if rest, ok := strings.CutPrefix(s, "ctrl+"); ok {
		return tea.KeyPressMsg{Code: []rune(rest)[0], Mod: tea.ModCtrl}
	}
	r := []rune(s)
	return tea.KeyPressMsg{Code: r[0], Text: s}
}

// send feeds one message to the model.
func send(m Model, msg tea.Msg) (Model, tea.Cmd) {
	next, cmd := m.Update(msg)
	return next.(Model), cmd
}

// press feeds key names in order and returns the final model and the last
// non-nil command.
func press(m Model, keys ...string) (Model, tea.Cmd) {
	var last tea.Cmd
	for _, k := range keys {
		var cmd tea.Cmd
		m, cmd = send(m, keyMsg(k))
		if cmd != nil {
			last = cmd
		}
	}
	return m, last
}

// typeText types s one rune at a time.
func typeText(m Model, s string) Model {
	for _, r := range s {
		m, _ = send(m, keyMsg(string(r)))
	}
	return m
}

// isQuit reports whether cmd is tea.Quit.
func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

// plain renders the model and strips ANSI codes.
func plain(m Model) string { return ansi.Strip(m.View().Content) }

// onHost returns a model with the cursor on the named host.
func onHost(m Model, name string) Model {
	m.selectHost(name)
	return m
}

func curKey(m Model) string {
	r, ok := m.current()
	if !ok {
		return ""
	}
	return r.key()
}
