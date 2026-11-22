// Package tui is the BubbleTea front-end for sshm.
//
// It talks to the app layer only (plus domain types). Every config mutation
// goes through app.AddHost/EditHost/DeleteHost/DuplicateHost, which re-read
// the file before writing, so the in-memory copy held here is display-only
// and can never clobber an external edit. Editing is offered only in managed
// mode (after 'sshm setup'); hosts outside the managed file are read-only.
//
// The TUI never execs ssh itself: on Enter it quits (restoring the terminal)
// and Run returns the chosen host name for the caller to connect.
package tui

import (
	"fmt"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// mode is what currently owns the keyboard.
type mode int

const (
	modeList      mode = iota // browsing the grouped list
	modeFilter                // typing into the filter input
	modeHelp                  // help overlay
	modeEditor                // edit / new host form
	modeDuplicate             // prompting for the duplicate's name
	modeDelete                // y/n delete confirmation
)

// Model is the top-level BubbleTea model.
type Model struct {
	app *app.App

	// Display-only copy of the config; refreshed by reload().
	hosts   []app.HostEntry
	issues  []domain.Issue
	loadErr error

	mode     mode
	expanded map[string]bool // group -> expanded (absent = collapsed)
	filter   textinput.Model // the "/" filter input; Value() is the query
	rows     []row           // visible rows, rebuilt by rebuild()
	cursor   int             // index into rows
	offset   int             // first visible row (scroll position)

	editor *editor         // non-nil in modeEditor
	prompt textinput.Model // duplicate-name input
	target string          // host name the duplicate/delete prompt acts on

	width, height int

	// managed / managedPath come from the last loaded snapshot. The e/n/d/D
	// keys work only when managed is true (every write then goes to the managed
	// file); reload re-evaluates it. A failed reload keeps the previous values.
	managed     bool
	managedPath string
	// managedProblem is Snapshot.ManagedProblem: a managed file that ssh reads
	// but sshm cannot load. Editing is then disabled with that text instead of
	// the "needs setup" hint.
	managedProblem string

	toast    string // one-line feedback, cleared on the next key
	toastErr bool

	selected string // host chosen for connect; read by Run after quit
}

// New builds a Model and loads the config. A load error is not fatal: it is
// shown in the status bar and the user can retry with "r".
func New(a *app.App) Model {
	m := Model{
		app:         a,
		managedPath: a.ManagedPath(), // until the first snapshot loads
		expanded:    map[string]bool{},
		filter:      newInput(""),
		prompt:      newInput(""),
		width:       80,
		height:      24,
	}
	m.reload()
	return m
}

// Selected returns the host chosen with Enter, or "" if none.
func (m Model) Selected() string { return m.selected }

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return nil }

func newInput(prompt string) textinput.Model {
	ti := textinput.New()
	ti.Prompt = prompt
	return ti
}

// Run starts the TUI and returns the host the user chose to connect to
// ("" if they quit without choosing). The terminal is restored before Run
// returns, so the caller may exec ssh.
func Run(a *app.App) (string, error) {
	final, err := tea.NewProgram(New(a)).Run()
	if err != nil {
		return "", fmt.Errorf("tui: %w", err)
	}
	m, ok := final.(Model)
	if !ok {
		return "", nil
	}
	return m.Selected(), nil
}
