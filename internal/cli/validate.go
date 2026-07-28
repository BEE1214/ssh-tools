package cli

import (
	"fmt"
	"os"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
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
				if i.Line > 0 {
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
		Short: "List detected groups and host counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			groups, err := a.ListGroups()
			if err != nil {
				return err
			}

			names := domain.GroupNames(groups)
			for _, name := range names {
				fmt.Printf("%s (%d)\n", name, len(groups[name]))
			}
			return nil
		},
	}
	return cmd
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate or repair the Host * defaults block",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			if err := a.InitDefaults(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Host * defaults block written to %s\n", a.ConfigPath())
			return nil
		},
	}
	return cmd
}