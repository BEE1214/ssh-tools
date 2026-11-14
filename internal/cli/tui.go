package cli

import (
	"errors"
	"os"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/adamdvorsky/ssh-tools/internal/tui"
)

// errNoTTY is returned instead of launching the TUI when stdin or stdout is
// not a terminal (pipes, cron, CI).
var errNoTTY = errors.New("sshm: no TTY; use 'sshm list'")

// stdioIsTerminal reports whether both stdin and stdout are terminals.
// A variable so tests never launch a real TUI.
var stdioIsTerminal = func() bool {
	return term.IsTerminal(os.Stdin.Fd()) && term.IsTerminal(os.Stdout.Fd())
}

// runTUI shows the host browser. The TUI never execs ssh itself: it quits
// (restoring the terminal) and returns the chosen host, which then goes
// through the same connect path as `sshm <host>`.
func runTUI(cmd *cobra.Command) error {
	if !stdioIsTerminal() {
		return errNoTTY
	}
	name, err := tui.Run(newApp())
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	return runConnect(cmd, name, nil)
}
