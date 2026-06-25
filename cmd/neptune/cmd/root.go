// Package cmd implements all command-line commands for the Neptune tool.
// It uses the Cobra framework to define commands, flags, and their execution logic.
//
// Commands:
//   - version: Display version and build information
//   - keygen: Generate Curve25519 key pairs
//   - encrypt: Encrypt files or directories
//   - decrypt: Decrypt files or directories
//   - download: Download files from remote URLs
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"neptune/internal/utils"
)

// rootCmd is the base command for the Neptune CLI tool.
// It provides the top-level help text and serves as the parent for all subcommands.
// Default completion command is disabled to keep the interface clean.
var rootCmd = &cobra.Command{
	Use:   "neptune",
	Short: "Neptune - A secure cross-platform encryption tool",
	Long: `Neptune is a secure cross-platform command-line encryption tool that uses
Curve25519 key exchange and Sosemanuk stream cipher for file and text encryption.

Features:
  - Generate Curve25519 key pairs
  - Encrypt files, directories or text with recipient's public key
  - Decrypt files, directories or text with your private key
  - Streaming encryption/decryption for large files
  - Parallel processing for batch operations
  - Remote key loading from HTTP/HTTPS URLs
  - Automatic memory cleanup for sensitive data
  - Secure file deletion with recovery prevention
  - Disk-scan mode for bulk operations
  - Cross-platform support (Windows, Linux)`,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

// Execute runs the root command and handles any errors that occur.
// If the error is a NeptuneError, it prints the full error message.
// Otherwise, it prints a generic error message.
// The program exits with code 1 on any error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if ne := utils.GetNeptuneError(err); ne != nil {
			fmt.Fprintln(os.Stderr, ne.FullError())
		} else {
			fmt.Fprintln(os.Stderr, fmt.Sprintf(": %v", err))
		}
		os.Exit(1)
	}
}
