package tui

import (
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// row is one visible line of the list: a group header or a host.
type row struct {
	header   bool
	group    string
	count    int
	expanded bool

	host  domain.Host
	gated bool // host is in a disabled group: not connectable/editable

	// included: the host is defined only in a file pulled in by Include
	// (Snapshot's Included flag, unchanged).
	included bool
	// reason is Snapshot's ReadOnlyReason: "" when sshm may edit, duplicate and
	// delete the host, else the refusal the write would return. The host stays
	// connectable.
	reason string
}

// key identifies a row across rebuilds so the cursor can follow it.
func (r row) key() string {
	if r.header {
		return "g:" + r.group
	}
	return "h:" + r.host.Name
}

// readOnly reports whether the TUI must not modify the host.
func (r row) readOnly() bool { return r.host.Source == domain.SourceDevPod }

// reload re-reads the config from disk. On failure the previous (stale)
// data stays on screen and the error is shown in the status bar.
func (m *Model) reload() {
	snap, err := m.app.Snapshot()
	if err != nil {
		m.loadErr = err
		return
	}
	m.loadErr = nil
	m.hosts = snap.Hosts
	m.issues = snap.Issues
	m.managed = snap.Managed
	m.managedPath = snap.ManagedPath
	m.managedProblem = snap.ManagedProblem
	m.rebuild()
}

// visibleHosts returns the hosts the list shows: everything except
// wildcard "Host *" defaults, which are not connectable targets.
func (m Model) visibleHosts() []domain.Host {
	hosts := make([]domain.Host, 0, len(m.hosts))
	for _, e := range m.hosts {
		if !e.IsWildcard() {
			hosts = append(hosts, e.Host)
		}
	}
	return hosts
}

// buildRows computes the visible rows: grouped (with collapse state) when no
// filter is active, otherwise a flat list of fuzzy matches.
func (m Model) buildRows() []row {
	hosts := m.visibleHosts()
	gated := map[string]bool{}
	included := map[string]bool{}
	reason := map[string]string{} // decided per name by the app layer
	for _, e := range m.hosts {
		if e.Gated {
			gated[e.Name] = true
		}
		if _, seen := reason[e.Name]; !seen {
			reason[e.Name] = e.ReadOnlyReason
		}
		if prev, seen := included[e.Name]; seen {
			included[e.Name] = prev && e.Included
		} else {
			included[e.Name] = e.Included
		}
	}

	var rows []row
	if q := m.filter.Value(); q != "" {
		byName := make(map[string]domain.Host, len(hosts))
		for _, h := range hosts {
			if _, dup := byName[h.Name]; !dup {
				byName[h.Name] = h
			}
		}
		for _, name := range domain.FuzzyMatch(hosts, q) {
			rows = append(rows, row{host: byName[name], gated: gated[name], included: included[name], reason: reason[name]})
		}
		return rows
	}

	groups := domain.GroupHosts(hosts)
	for _, g := range domain.GroupNames(groups) {
		exp := m.expanded[g]
		rows = append(rows, row{header: true, group: g, count: len(groups[g]), expanded: exp})
		if !exp {
			continue
		}
		for _, h := range groups[g] {
			rows = append(rows, row{group: g, host: h, gated: gated[h.Name], included: included[h.Name], reason: reason[h.Name]})
		}
	}
	return rows
}

// hostCount is the number of host rows the header's "[N hosts]" reports:
// matches while filtering, all hosts otherwise.
func (m Model) hostCount() int {
	if m.filter.Value() != "" {
		return len(m.rows)
	}
	return len(m.visibleHosts())
}

// rebuild recomputes rows and keeps the cursor on the same row if it still
// exists (otherwise it stays at the same index, clamped).
func (m *Model) rebuild() {
	keep := ""
	if r, ok := m.current(); ok {
		keep = r.key()
	}
	m.rows = m.buildRows()
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if keep != "" {
		m.moveTo(keep)
	}
	m.fixScroll()
}

// current returns the row under the cursor.
func (m Model) current() (row, bool) {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return row{}, false
	}
	return m.rows[m.cursor], true
}

// moveTo puts the cursor on the row with the given key.
func (m *Model) moveTo(key string) bool {
	for i, r := range m.rows {
		if r.key() == key {
			m.cursor = i
			return true
		}
	}
	return false
}

// selectHost puts the cursor on the named host, expanding its group and, if
// a filter hides it, clearing the filter.
func (m *Model) selectHost(name string) {
	for g, hs := range domain.GroupHosts(m.visibleHosts()) {
		for _, h := range hs {
			if h.Name == name {
				m.expanded[g] = true
			}
		}
	}
	m.rows = m.buildRows()
	if !m.moveTo("h:"+name) && m.filter.Value() != "" {
		m.filter.Reset()
		m.rows = m.buildRows()
		m.moveTo("h:" + name)
	}
	m.fixScroll()
}

func (m *Model) move(delta int) {
	m.cursor += delta
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.fixScroll()
}

// setExpanded expands or collapses the group under the cursor. Collapsing
// from a host row moves the cursor to its group header. No-op while
// filtering (the list is flat).
func (m *Model) setExpanded(exp bool) {
	r, ok := m.current()
	if !ok || m.filter.Value() != "" {
		return
	}
	m.expanded[r.group] = exp
	m.rebuild()
	m.moveTo("g:" + r.group)
	m.fixScroll()
}

// bodyHeight is the number of list rows that fit between the header and
// footer (2 lines each).
func (m Model) bodyHeight() int {
	if h := m.height - 4; h > 1 {
		return h
	}
	return 1
}

// fixScroll keeps the cursor inside the viewport.
func (m *Model) fixScroll() {
	bh := m.bodyHeight()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+bh {
		m.offset = m.cursor - bh + 1
	}
	if limit := len(m.rows) - bh; m.offset > limit {
		m.offset = limit
	}
	if m.offset < 0 {
		m.offset = 0
	}
}
