package cli

import (
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