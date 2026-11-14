package tui

import "charm.land/lipgloss/v2"

// Plain ANSI-256 colors only: no themes, no config.
var (
	styleTitle    = lipgloss.NewStyle().Bold(true)
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	styleSelected = lipgloss.NewStyle().Reverse(true)
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleErr      = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	styleGroup    = lipgloss.NewStyle().Bold(true)
	styleLabel    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

// fit truncates every line of s to at most w cells.
func fit(s string, w int) string {
	if w < 1 {
		w = 1
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(s)
}
