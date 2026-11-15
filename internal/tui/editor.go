package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Editor field indexes. fName is read-only when editing (the app layer has
// no rename operation).
const (
	fName = iota
	fHostName
	fUser
	fPort
	fIdentity
	fProxyJump
	numFields
)

// field describes one form row. key is the app.EditHost change key.
type field struct {
	label string
	key   string
}

var editorFields = [numFields]field{
	fName:      {"Host", "name"},
	fHostName:  {"HostName", "hostname"},
	fUser:      {"User", "user"},
	fPort:      {"Port", "port"},
	fIdentity:  {"IdentityFile", "identityfile"},
	fProxyJump: {"ProxyJump", "proxyjump"},
}

// editor is the form state for creating or editing a host.
type editor struct {
	isNew  bool
	name   string // host being edited (empty when isNew)
	orig   [numFields]string
	inputs [numFields]textinput.Model
	focus  int

	issues []domain.Issue // last validation result (errors block save)
	err    string         // last save failure
}

func newEditor(h *domain.Host) *editor {
	e := &editor{isNew: h == nil}
	if h != nil {
		e.name = h.Name
		e.orig = [numFields]string{
			fName: h.Name, fHostName: h.HostName, fUser: h.User,
			fPort: h.Port, fIdentity: h.IdentityFile, fProxyJump: h.ProxyJump,
		}
	} else {
		// Same default as `sshm add`.
		e.orig[fIdentity] = domain.DefaultIdentityFile
	}
	for i := range e.inputs {
		e.inputs[i] = newInput("")
		e.inputs[i].SetValue(e.orig[i])
	}
	e.setFocus(e.first())
	return e
}

// first is the first focusable field.
func (e *editor) first() int {
	if e.isNew {
		return fName
	}
	return fHostName
}

func (e *editor) setFocus(i int) {
	e.inputs[e.focus].Blur()
	e.focus = i
	e.inputs[i].Focus() // blink cmd intentionally dropped: steady cursor
}

// step moves focus by delta, wrapping over the focusable fields.
func (e *editor) step(delta int) {
	lo := e.first()
	n := numFields - lo
	e.setFocus(lo + (e.focus-lo+delta+n)%n)
}

func (e *editor) value(i int) string { return strings.TrimSpace(e.inputs[i].Value()) }

// changes returns the fields whose value differs from the original, keyed
// for app.EditHost.
func (e *editor) changes() map[string]string {
	ch := map[string]string{}
	for i := fHostName; i < numFields; i++ {
		if v := e.value(i); v != strings.TrimSpace(e.orig[i]) {
			ch[editorFields[i].key] = v
		}
	}
	return ch
}

// newHost builds the host an "n" editor would add.
func (e *editor) newHost() domain.Host {
	return domain.Host{
		Name:         e.value(fName),
		HostName:     e.value(fHostName),
		User:         e.value(fUser),
		Port:         e.value(fPort),
		IdentityFile: e.value(fIdentity),
		ProxyJump:    e.value(fProxyJump),
	}
}

// validateEditor previews the app layer's validation for the current input and
// stores the result. It returns false if there are blocking errors.
func (m *Model) validateEditor() bool {
	e := m.editor
	var (
		issues []domain.Issue
		err    error
	)
	if e.isNew {
		issues, err = m.app.CheckNewHost(e.newHost())
	} else {
		issues, err = m.app.CheckEdit(e.name, e.changes())
	}
	e.err = ""
	if err != nil {
		e.err = err.Error()
		e.issues = nil
		return false
	}
	e.issues = issues
	return !domain.HasErrors(issues)
}

func (m *Model) openEditor(h *domain.Host) {
	m.editor = newEditor(h)
	m.mode = modeEditor
	m.validateEditor()
}

// closeEditor returns to the list.
func (m *Model) closeEditor() {
	m.editor = nil
	m.mode = modeList
}

// updateEditor handles a key press in modeEditor.
func (m Model) updateEditor(k tea.KeyPressMsg) (Model, tea.Cmd) {
	e := m.editor
	switch k.String() {
	case "esc", "ctrl+c":
		m.closeEditor()
	case "tab", "down":
		e.step(1)
		m.validateEditor()
	case "shift+tab", "up":
		e.step(-1)
		m.validateEditor()
	case "enter":
		if e.focus == numFields-1 {
			m.saveEditor()
		} else {
			e.step(1)
			m.validateEditor()
		}
	case "ctrl+s":
		m.saveEditor()
	default:
		e.err = ""
		e.inputs[e.focus], _ = e.inputs[e.focus].Update(k)
	}
	return m, nil
}

// saveEditor validates and, if there are no errors, writes through the app
// layer. Warnings do not block; they are reported in the toast.
func (m *Model) saveEditor() {
	e := m.editor
	if !m.validateEditor() {
		return
	}

	var (
		name string
		err  error
	)
	if e.isNew {
		h := e.newHost()
		name = h.Name
		err = m.app.AddHost(h)
	} else {
		name = e.name
		ch := e.changes()
		if len(ch) == 0 {
			m.closeEditor()
			m.setToast("no changes", false)
			return
		}
		err = m.app.EditHost(name, ch)
	}
	if err != nil {
		e.err = err.Error()
		return
	}

	warnings := 0
	for _, i := range e.issues {
		if i.Severity == domain.SeverityWarning {
			warnings++
		}
	}
	m.closeEditor()
	m.reload()
	m.selectHost(name)
	msg := fmt.Sprintf("saved %s", name)
	if warnings > 0 {
		msg += fmt.Sprintf(" (%d warning%s)", warnings, plural(warnings))
	}
	m.setToast(msg, false)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
