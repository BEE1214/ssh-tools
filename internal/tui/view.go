package tui

import (
	"fmt"
	"path"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// View implements tea.Model. Layout (always exactly m.height lines):
// 2 header lines, body, 2 footer lines (status + key hints).
func (m Model) View() tea.View {
	var s string
	switch m.mode {
	case modeEditor:
		s = m.editorView()
	case modeHelp:
		s = m.helpView()
	default:
		s = m.listView()
	}
	v := tea.NewView(s)
	v.AltScreen = true
	return v
}

func (m Model) listView() string {
	bh := m.bodyHeight()

	lines := []string{m.titleLine(), m.filterLine()}

	nameW, connW := m.columnWidths()
	end := min(m.offset+bh, len(m.rows))
	for i := m.offset; i < end; i++ {
		lines = append(lines, m.rowLine(m.rows[i], nameW, connW, i == m.cursor))
	}
	if len(m.rows) == 0 {
		lines = append(lines, styleDim.Render("  no hosts"))
	}
	return m.frame(lines, m.statusLine(), m.hintsLine())
}

// frame pads body lines to the body height, appends the footer and fits
// every line to the window width.
func (m Model) frame(head []string, status, hints string) string {
	room := max(0, m.height-2)
	lines := make([]string, 0, m.height)
	lines = append(lines, head[:min(len(head), room)]...)
	for len(lines) < room {
		lines = append(lines, "")
	}
	lines = append(lines, status, hints)
	if m.height < 2 { // degenerate window: show hints only
		lines = []string{hints}
	}
	for i, l := range lines {
		lines[i] = fit(l, m.width)
	}
	return strings.Join(lines, "\n")
}

func (m Model) titleLine() string {
	n := m.hostCount()
	count := fmt.Sprintf("[%d host%s]", n, plural(n))
	title := styleTitle.Render("SSH Manager")
	gap := m.width - lipgloss.Width(title) - lipgloss.Width(count)
	if gap < 1 {
		return title
	}
	return title + strings.Repeat(" ", gap) + styleDim.Render(count)
}

func (m Model) filterLine() string {
	switch {
	case m.mode == modeFilter:
		return "Filter: " + m.filter.View()
	case m.filter.Value() != "":
		return "Filter: " + m.filter.Value() + styleDim.Render("  (esc clears, / edits)")
	}
	return styleDim.Render("/ to filter, ? for help")
}

// connText is the "user @ host:port" column.
func connText(h domain.Host) string {
	return fmt.Sprintf("%s @ %s:%s", h.DisplayUser(), h.DisplayHost(), h.CanonicalPort())
}

// columnWidths returns the name and connection column widths so host rows
// line up (capped so one long name cannot push everything off screen).
func (m Model) columnWidths() (nameW, connW int) {
	for _, r := range m.rows {
		if !r.header {
			nameW = max(nameW, lipgloss.Width(r.host.Name))
			connW = max(connW, lipgloss.Width(connText(r.host)))
		}
	}
	return min(nameW, 28), min(connW, 40)
}

func (m Model) rowLine(r row, nameW, connW int, selected bool) string {
	if r.header {
		arrow := "▸"
		if r.expanded {
			arrow = "▾"
		}
		text := fmt.Sprintf("%s %s (%d host%s)", arrow, r.group, r.count, plural(r.count))
		if selected {
			return styleSelected.Render(text)
		}
		return styleGroup.Render(text)
	}

	h := r.host
	indent := "    "
	if m.filter.Value() != "" {
		indent = "  "
	}
	name := padRight(h.Name, nameW)
	conn := padRight(connText(h), connW)
	key := "no key"
	if h.HasIdentityFile() {
		key = path.Base(h.IdentityFile)
	}
	var tags []string
	if r.gated {
		tags = append(tags, "[disabled]")
	}
	if r.readOnly() {
		tags = append(tags, "[read-only]")
	}
	switch {
	case !m.managed:
		// Legacy mode: today's tag, and never [main].
		if r.included {
			tags = append(tags, "[included]")
		}
	case r.reason != "":
		// Managed mode: a host outside the managed file. Hosts of the managed
		// file (no reason) show neither tag.
		if r.included {
			tags = append(tags, "[included]")
		} else {
			tags = append(tags, "[main]")
		}
	}
	if m.filter.Value() != "" && !r.gated {
		// Flat list: show which group each match belongs to.
		tags = append(tags, "("+groupLabel(h)+")")
	}
	tag := strings.Join(tags, " ")

	join := func(name, conn, key, tag string) string {
		parts := []string{name, conn, key}
		if tag != "" {
			parts = append(parts, tag)
		}
		return indent + strings.Join(parts, "  ")
	}
	switch {
	case selected:
		return styleSelected.Render(join(name, conn, key, tag))
	case r.gated:
		return styleDim.Faint(true).Render(join(name, conn, key, tag))
	}
	keyStyled := styleLabel.Render(key)
	if !h.HasIdentityFile() {
		// Missing key: dimmed warning.
		keyStyled = styleWarn.Faint(true).Render(key)
	}
	return join(name, styleLabel.Render(conn), keyStyled, styleDim.Render(tag))
}

func groupLabel(h domain.Host) string {
	if h.Group == "" {
		return "ungrouped"
	}
	return h.Group
}

func padRight(s string, w int) string {
	if gap := w - lipgloss.Width(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s
}

// statusLine: toast > prompt > load error > validation summary.
func (m Model) statusLine() string {
	switch {
	case m.mode == modeDuplicate:
		return fmt.Sprintf("Duplicate %s as: %s", m.target, m.prompt.View()) + m.toastSuffix()
	case m.mode == modeDelete:
		return styleWarn.Render(fmt.Sprintf("Delete %s? (y/n)", m.target))
	case m.toast != "":
		if m.toastErr {
			return styleErr.Render(m.toast)
		}
		return styleOK.Render(m.toast)
	case m.loadErr != nil:
		return styleErr.Render("config error: " + m.loadErr.Error() + " (r to retry)")
	}
	errs, warns := 0, 0
	for _, i := range m.issues {
		switch i.Severity {
		case domain.SeverityError:
			errs++
		case domain.SeverityWarning:
			warns++
		}
	}
	switch {
	case errs > 0:
		return styleErr.Render(fmt.Sprintf("%d error%s, %d warning%s — run 'sshm validate'", errs, plural(errs), warns, plural(warns)))
	case warns > 0:
		return styleWarn.Render(fmt.Sprintf("%d warning%s — run 'sshm validate'", warns, plural(warns)))
	}
	return styleDim.Render("no issues")
}

func (m Model) toastSuffix() string {
	if m.toast == "" {
		return ""
	}
	return "  " + styleErr.Render(m.toast)
}

func (m Model) hintsLine() string {
	switch m.mode {
	case modeFilter:
		return styleDim.Render("type to filter  ↑↓ move  enter apply  esc clear")
	case modeDuplicate:
		return styleDim.Render("enter duplicate  esc cancel")
	case modeDelete:
		return styleDim.Render("y delete  n cancel")
	}
	if !m.managed {
		return styleDim.Render("↑↓ move  →← fold  enter connect  / filter  r reload  ? help  q quit")
	}
	return styleDim.Render("↑↓ move  →← fold  enter connect  / filter  e edit  n new  d dup  D del  ? help  q quit")
}

var helpLines = []string{
	"Keys",
	"",
	"  ↑/k ↓/j      move cursor",
	"  →/l ←/h      expand / collapse group",
	"  enter        connect to host (toggle on a group)",
	"  /            filter (fuzzy); enter applies, esc clears",
	"  e            edit host",
	"  n            new host",
	"  d            duplicate host",
	"  D            delete host (asks y/n)",
	"  r            reload config from disk",
	"  q / esc      quit",
	"",
	"Editor: tab/shift+tab fields, enter on last field or ctrl+s saves, esc cancels.",
	"Tagged hosts cannot be edited, duplicated or deleted (edits go to the managed file):",
	"  [main]      in the main file; 'sshm import' moves it to the managed file",
	"  [included]  in another included file; sshm does not manage it",
	"  [read-only] DevPod host     [disabled] its group is disabled",
	"",
	"press any key to close",
}

// readOnlyHelpLines is the help text in legacy mode (before 'sshm setup').
var readOnlyHelpLines = []string{
	"Keys",
	"",
	"  ↑/k ↓/j      move cursor",
	"  →/l ←/h      expand / collapse group",
	"  enter        connect to host (toggle on a group)",
	"  /            filter (fuzzy); enter applies, esc clears",
	"  r            reload config from disk",
	"  q / esc      quit",
	"",
	"Editing is available after 'sshm setup'.",
	"",
	"press any key to close",
}

func (m Model) helpView() string {
	lines := []string{m.titleLine(), ""}
	if m.managed {
		lines = append(lines, helpLines...)
	} else {
		lines = append(lines, readOnlyHelpLines...)
	}
	return m.frame(lines, "", styleDim.Render("press any key to close"))
}

func (m Model) editorView() string {
	e := m.editor
	title := "Edit: " + e.name
	if e.isNew {
		title = "New host"
	}
	lines := []string{styleTitle.Render(title), ""}

	labelW := 0
	for _, f := range editorFields {
		labelW = max(labelW, len(f.label))
	}
	inputW := max(10, m.width-labelW-6)
	for i, f := range editorFields {
		in := e.inputs[i]
		in.SetWidth(inputW)
		label := padRight(f.label+":", labelW+1)
		switch {
		case !e.isNew && i == fName:
			// Read-only when editing: there is no rename operation.
			lines = append(lines, styleLabel.Render(label)+" "+styleDim.Render(e.inputs[i].Value()+"  (read-only)"))
		case i == e.focus:
			lines = append(lines, styleTitle.Render(label)+" "+in.View())
		default:
			lines = append(lines, styleLabel.Render(label)+" "+in.View())
		}
	}

	lines = append(lines, "")
	if e.err != "" {
		lines = append(lines, styleErr.Render("✗ "+e.err))
	}
	for _, i := range e.issues {
		switch i.Severity {
		case domain.SeverityError:
			lines = append(lines, styleErr.Render("✗ "+i.Message))
		case domain.SeverityWarning:
			lines = append(lines, styleWarn.Render("⚠ "+i.Message))
		}
	}
	hints := "tab/shift+tab field  enter next/save  ctrl+s save  esc cancel"
	return m.frame(lines, "", styleDim.Render(hints))
}
