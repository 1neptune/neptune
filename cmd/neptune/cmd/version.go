package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	Version   = "v1.1.0"
	BuildDate = "2026-06-13"
)

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

func init() {
	rootCmd.AddCommand(versionCmd)
}