package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
)

// Update implements tea.Model. All file I/O happens through the app layer;
// there is no terminal access here, so tests can drive it with plain msgs.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.fixScroll()
		return m, nil

	case tea.KeyPressMsg:
		m.toast, m.toastErr = "", false
		var cmd tea.Cmd
		switch m.mode {
		case modeFilter:
			m, cmd = m.updateFilter(msg)
		case modeHelp:
			m, cmd = m.updateHelp(msg)
		case modeEditor:
			m, cmd = m.updateEditor(msg)
		case modeDuplicate:
			m, cmd = m.updateDuplicate(msg)
		case modeDelete:
			m, cmd = m.updateDelete(msg)
		default:
			m, cmd = m.updateList(msg)
		}
		return m, cmd

	case tea.PasteMsg:
		switch m.mode {
		case modeFilter:
			m.filter, _ = m.filter.Update(msg)
			m.rebuild()
			m.cursor = 0
			m.fixScroll()
		case modeDuplicate:
			m.prompt, _ = m.prompt.Update(msg)
		case modeEditor:
			m.editor.inputs[m.editor.focus], _ = m.editor.inputs[m.editor.focus].Update(msg)
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) setToast(s string, isErr bool) { m.toast, m.toastErr = s, isErr }

// updateList handles keys while browsing.
func (m Model) updateList(k tea.KeyPressMsg) (Model, tea.Cmd) {
	switch k.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		if m.filter.Value() != "" {
			m.clearFilter()
			return m, nil
		}
		return m, tea.Quit
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "right", "l":
		m.setExpanded(true)
	case "left", "h":
		m.setExpanded(false)
	case "enter":
		return m.activate()
	case "/":
		m.mode = modeFilter
		m.filter.Focus() // blink cmd intentionally dropped: steady cursor
		m.filter.CursorEnd()
	case "r":
		m.reload()
		if m.loadErr == nil {
			m.setToast("reloaded", false)
		}
	case "?":
		m.mode = modeHelp
	case "e", "n", "d", "D":
		if !m.editable {
			m.setToast("editing is disabled in the TUI for now; use the sshm CLI", true)
			return m, nil
		}
		switch k.String() {
		case "e":
			m.startEdit()
		case "n":
			m.openEditor(nil)
		case "d":
			m.startDuplicate()
		case "D":
			m.startDelete()
		}
	}
	return m, nil
}

// activate is Enter in the list: toggle a group, or choose a host to
// connect to. The program quits; the caller execs ssh.
func (m Model) activate() (Model, tea.Cmd) {
	r, ok := m.current()
	if !ok {
		return m, nil
	}
	if r.header {
		m.setExpanded(!r.expanded)
		return m, nil
	}
	if r.gated {
		m.setToast(disabledMsg(r), true)
		return m, nil
	}
	m.selected = r.host.Name
	return m, tea.Quit
}

func disabledMsg(r row) string {
	g := r.host.Group
	if g == "" {
		g = "ungrouped"
	}
	return fmt.Sprintf("%s is in disabled group %q — run 'sshm groups enable %s'", r.host.Name, g, g)
}

// hostForChange returns the host under the cursor if it may be modified;
// otherwise it sets an explanatory toast and returns false.
func (m *Model) hostForChange() (row, bool) {
	r, ok := m.current()
	if !ok || r.header {
		return row{}, false
	}
	switch {
	case r.gated:
		m.setToast(disabledMsg(r), true)
	case r.readOnly():
		m.setToast(r.host.Name+" is read-only (managed by DevPod)", true)
	default:
		return r, true
	}
	return row{}, false
}

func (m *Model) startEdit() {
	if r, ok := m.hostForChange(); ok {
		h := r.host
		m.openEditor(&h)
	}
}

func (m *Model) startDuplicate() {
	if r, ok := m.hostForChange(); ok {
		m.target = r.host.Name
		m.prompt.Reset()
		m.prompt.Focus()
		m.mode = modeDuplicate
	}
}

func (m *Model) startDelete() {
	if r, ok := m.hostForChange(); ok {
		m.target = r.host.Name
		m.mode = modeDelete
	}
}

// clearFilter drops the filter and returns to the list, keeping the cursor
// on the host that was selected.
func (m *Model) clearFilter() {
	name := ""
	if r, ok := m.current(); ok && !r.header {
		name = r.host.Name
	}
	m.filter.Reset()
	m.filter.Blur()
	m.mode = modeList
	m.rebuild()
	if name != "" {
		m.selectHost(name)
	}
}

// updateFilter handles keys while typing the filter. Enter keeps the filter
// applied and returns to normal list keys; Esc clears it.
func (m Model) updateFilter(k tea.KeyPressMsg) (Model, tea.Cmd) {
	switch k.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.clearFilter()
	case "enter":
		m.filter.Blur()
		m.mode = modeList
	case "up":
		m.move(-1)
	case "down":
		m.move(1)
	default:
		m.filter, _ = m.filter.Update(k)
		m.rebuild()
		m.cursor = 0
		m.fixScroll()
	}
	return m, nil
}

func (m Model) updateHelp(k tea.KeyPressMsg) (Model, tea.Cmd) {
	if k.String() == "ctrl+c" {
		return m, tea.Quit
	}
	m.mode = modeList
	return m, nil
}

// updateDuplicate handles keys in the "duplicate as" prompt.
func (m Model) updateDuplicate(k tea.KeyPressMsg) (Model, tea.Cmd) {
	switch k.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.prompt.Blur()
		m.mode = modeList
	case "enter":
		name := strings.TrimSpace(m.prompt.Value())
		if err := m.app.CheckHostName(name); err != nil {
			m.setToast(err.Error(), true)
			return m, nil
		}
		m.prompt.Blur()
		m.mode = modeList
		if err := m.app.DuplicateHost(m.target, name); err != nil {
			m.setToast(err.Error(), true)
			return m, nil
		}
		m.reload()
		m.selectHost(name)
		m.setToast(fmt.Sprintf("duplicated %s as %s", m.target, name), false)
	default:
		m.prompt, _ = m.prompt.Update(k)
	}
	return m, nil
}

// updateDelete handles the y/n delete confirmation.
func (m Model) updateDelete(k tea.KeyPressMsg) (Model, tea.Cmd) {
	switch k.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "y":
		m.mode = modeList
		if err := m.app.DeleteHost(m.target); err != nil {
			m.setToast(err.Error(), true)
			return m, nil
		}
		m.reload() // cursor index is kept, so it lands on the next row
		m.setToast("deleted "+m.target, false)
	case "n", "esc":
		m.mode = modeList
	}
	return m, nil
}
