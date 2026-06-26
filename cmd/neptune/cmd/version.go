package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version constants define the current version of the Neptune tool.
// These are set at build time and displayed by the version command.
const (
	Version   = "v1.2.20" // Semantic version number
	BuildDate = "2026-06-26" // Date of the current build
)

// versionCmd displays version and build information for Neptune.
// It shows the version number, build date, and the encryption algorithms used.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Long:  `Display the version number and build information for Neptune.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Neptune Encryption Tool\n")
		fmt.Printf("Version:    %s\n", Version)
		fmt.Printf("Build Date: %s\n", BuildDate)
		fmt.Printf("Algorithm:  Curve25519 + Sosemanuk\n")
	},
}

// init registers the version command with the root command.
// This is called automatically when the package is imported.
func init() {
	rootCmd.AddCommand(versionCmd)
}
