package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// hostCompletion is a ValidArgsFunction that returns fuzzy-matched host names
// for shell completion. ToComplete is what the user has typed so far.
func hostCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		// Already have the host argument — no more completion.
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	a := newApp()
	matches, err := a.HostNamesForCompletion(toComplete)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	// Filter out duplicates (duplicate host names exist in the config).
	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}

	return result, cobra.ShellCompDirectiveNoFileComp
}

// hostFlagCompletion is a FlagCompletionFunc — same fuzzy host-name matching
// as hostCompletion, but for flag *values* (e.g. --proxyjump <TAB>).
// The cmd/args/toComplete signature is required by cobra's
// RegisterFlagCompletionFunc.
func hostFlagCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	a := newApp()
	matches, err := a.HostNamesForCompletion(toComplete)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	seen := make(map[string]bool)
	var result []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			result = append(result, m)
		}
	}

	return result, cobra.ShellCompDirectiveNoFileComp
}

// registerHostFlagCompletion wires host-name completion onto the given flag
// names. Call it after the flags are registered on the command.
func registerHostFlagCompletion(cmd *cobra.Command, flagNames ...string) {
	for _, name := range flagNames {
		_ = cmd.RegisterFlagCompletionFunc(name, hostFlagCompletion)
	}
}

// groupCompletion is a ValidArgsFunction that completes group names (all
// groups with hosts, plus currently disabled ones).
func groupCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	a := newApp()
	states, err := a.ListGroupsState()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var result []string
	for _, gs := range states {
		if strings.HasPrefix(gs.Group, toComplete) {
			result = append(result, gs.Group)
		}
	}
	return result, cobra.ShellCompDirectiveNoFileComp
}

// disabledGroupCompletion is a ValidArgsFunction that completes only the
// names of currently disabled groups (for `sshm groups enable <TAB>`).
func disabledGroupCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	a := newApp()
	states, err := a.ListGroupsState()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var result []string
	for _, gs := range states {
		if len(gs.Disabled) > 0 && strings.HasPrefix(gs.Group, toComplete) {
			result = append(result, gs.Group)
		}
	}
	return result, cobra.ShellCompDirectiveNoFileComp
}