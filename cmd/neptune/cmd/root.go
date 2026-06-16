package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"neptune/internal/utils"
)

var rootCmd = &cobra.Command{
	Use:   "neptune",
	Short: "Neptune - A secure encryption tool using Curve25519 and Sosemanuk",
	Long: `Neptune is a command-line encryption tool that provides secure file and text encryption
using Curve25519 key exchange and Sosemanuk stream cipher.

Features:
  - Generate Curve25519 key pairs
  - Encrypt files or text with recipient's public key
  - Decrypt files or text with your private key
  - Support for multiple encoding formats (hex, base64)`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Check if error is a NeptuneError
		if ne := utils.GetNeptuneError(err); ne != nil {
			// Print full error with suggestion
			fmt.Fprintln(os.Stderr, ne.FullError())
		} else {
			// Print standard error
			fmt.Fprintln(os.Stderr, fmt.Sprintf(": %v", err))
		}
		os.Exit(1)
	}
}