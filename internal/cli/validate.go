package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check config for issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			issues, err := a.Validate()
			if err != nil {
				return err
			}

			if len(issues) == 0 {
				fmt.Println("No issues found.")
				return nil
			}

			for _, i := range issues {
				location := ""
				switch {
				case i.File != "" && i.Line > 0:
					location = fmt.Sprintf(" (%s line %d)", i.File, i.Line)
				case i.File != "":
					location = fmt.Sprintf(" (%s)", i.File)
				case i.Line > 0:
					location = fmt.Sprintf(" (line %d)", i.Line)
				}
				if i.HostName != "" {
					fmt.Fprintf(os.Stderr, "%s [%s] %s: %s%s\n", i.Severity, i.Rule, i.HostName, i.Message, location)
				} else {
					fmt.Fprintf(os.Stderr, "%s [%s] %s%s\n", i.Severity, i.Rule, i.Message, location)
				}
			}

			return nil
		},
	}
	return cmd
}

func newGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "List groups with enable/disable state",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			states, err := a.ListGroupsState()
			if err != nil {
				return err
			}

			for _, gs := range states {
				if len(gs.Disabled) > 0 {
					fmt.Printf("%s (disabled: %s)\n", gs.Group, strings.Join(gs.Disabled, ", "))
				} else {
					fmt.Printf("%s (%d)\n", gs.Group, gs.Total)
				}
			}
			return nil
		},
	}
	cmd.AddCommand(newGroupsDisableCmd(), newGroupsEnableCmd())
	return cmd
}

func newGroupsDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable <group>",
		Short: "Disable a group: comment its host blocks out of the ssh config",
		Long: `Disable a group: the group's host blocks are commented out of
~/.ssh/config under "# sshm disabled" markers, the group is recorded in a
sidecar state file (~/.ssh/config.sshm-groups), and sshm connect/copy refuse
its hosts. Raw ` + "`ssh <host>`" + ` also fails to resolve — a hard gate for
e.g. production deployments.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: groupCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			if err := a.DisableGroup(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "group %q disabled — blocks commented out of %s\n", args[0], a.ManagedPath())
			return nil
		},
	}
	return cmd
}

func newGroupsEnableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <group>",
		Short: "Re-enable a disabled group (restore its host blocks verbatim)",
		Long: `Re-enable a previously disabled group: the host blocks between the
group's "# sshm disabled" markers are restored byte-for-byte and the group is
removed from the sidecar state file.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: disabledGroupCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			if err := a.EnableGroup(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "group %q enabled — blocks restored in %s\n", args[0], a.ManagedPath())
			return nil
		},
	}
	return cmd
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate the Host * defaults block (sets up a fresh machine first)",
		Long: `Generate the hardened Host * defaults block (keepalive,
StrictHostKeyChecking accept-new, modern KEX/ciphers/MACs).

On a machine without an ssh config, init does what 'sshm setup' does (an empty
managed file, included from a new ssh config) and stops there; run it again to
add the block. On a config that is set up, a new block is appended as the LAST
host block of the main file: ssh uses the first value found for each option, so
a catch-all Host * only supplies defaults when it comes after your specific
hosts. An existing Host * block is never rewritten; a note says where it is.
An ssh config that exists but is not set up is refused: run 'sshm setup'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			res, fresh, err := a.InitFresh()
			if err != nil {
				return err
			}
			if fresh {
				printSetupResult(res, "")
				fmt.Fprintf(os.Stderr, "created an empty %s; run 'sshm init' again to add the default Host * block\n", a.ManagedPath())
				return nil
			}
			written, note, err := a.InitDefaultsReport()
			if err != nil {
				return err
			}
			if note != "" {
				fmt.Fprintln(os.Stderr, "note: "+note)
			}
			if written {
				fmt.Fprintf(os.Stderr, "Host * defaults block written to %s\n", a.ConfigPath())
			}
			return nil
		},
	}
	return cmd
}
