package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	neptuneCurve25519 "neptune/pkg/curve25519"
	"neptune/internal/utils"
)

// keygen command flags - these are populated by Cobra from command-line arguments.
var (
	// keygenOutputDir specifies the directory where generated key files will be saved.
	// Defaults to the current working directory.
	keygenOutputDir string

	// keygenEncoding specifies the encoding format for the generated keys.
	// Supported formats: hex, base64, base64url. Defaults to hex.
	keygenEncoding string

	// keygenName specifies the base name for the generated key files.
	// Files will be named as <name>_private.key and <name>_public.key.
	keygenName string
)

// keygenCmd generates a new Curve25519 key pair for encryption and decryption.
//
// The generated key pair consists of:
//   - Private key: Used for decrypting messages sent to you. Must be kept secret.
//   - Public key: Used by others to encrypt messages for you. Can be freely shared.
//
// The command saves both keys to separate files and also prints the public key
// to the console for easy sharing.
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new Curve25519 key pair",
	Long: `Generate a new Curve25519 key pair for encryption and decryption.

The key pair consists of a private key (for decryption) and a public key (for encryption).
You should keep your private key secure and share your public key with others who want to send you encrypted data.

Examples:
  # Generate a key pair with default settings (hex encoding, current directory)
  neptune keygen

  # Generate a key pair with base64 encoding
  neptune keygen --encoding base64

  # Generate a key pair and save to specific directory
  neptune keygen --output ./keys

  # Generate a key pair with custom name
  neptune keygen --name mykey --output ./keys`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate and parse the encoding type from user input
		encoding, err := utils.ParseEncodingType(keygenEncoding)
		if err != nil {
			return err
		}

		// Generate a cryptographically secure Curve25519 key pair
		// Uses crypto/rand for secure random number generation
		keyPair, err := neptuneCurve25519.GenerateKeyPair()
		if err != nil {
			return utils.NewKeyWriteError("", err)
		}

		// Create the output directory if it doesn't already exist
		if keygenOutputDir != "" {
			if err := utils.EnsureDirectory(keygenOutputDir); err != nil {
				return err
			}
		}

		// Construct the full file paths for both key files
		privateKeyFile := filepath.Join(keygenOutputDir, keygenName+"_private.key")
		publicKeyFile := filepath.Join(keygenOutputDir, keygenName+"_public.key")

		// Save the complete key pair (both private and public keys) to the private key file
		// Format: first line = private key, second line = public key
		if err := neptuneCurve25519.SaveKeyPairToFile(keyPair, privateKeyFile, neptuneCurve25519.EncodingType(encoding)); err != nil {
			return utils.NewKeyWriteError(privateKeyFile, err)
		}

		// Save only the public key to a separate file for easy sharing
		if err := neptuneCurve25519.SavePublicKeyToFile(keyPair.PublicKey, publicKeyFile, neptuneCurve25519.EncodingType(encoding)); err != nil {
			return utils.NewKeyWriteError(publicKeyFile, err)
		}

		// Output generation results to the user
		utils.PrintSuccess("Key pair generated successfully")
		utils.PrintInfo("Private key saved to: %s", privateKeyFile)
		utils.PrintInfo("Public key saved to: %s", publicKeyFile)
		utils.PrintInfo("Encoding format: %s", keygenEncoding)
		fmt.Printf("\nPublic key (for sharing):\n%s\n", neptuneCurve25519.SerializePublicKey(keyPair.PublicKey, neptuneCurve25519.EncodingType(encoding)))
		utils.PrintWarning("Keep your private key secure!")

		return nil
	},
}

// init registers the keygen command and its flags with the root command.
// This is called automatically when the package is imported.
//
// Flags:
//   --output, -o    Output directory for key files (default: current directory)
//   --encoding, -e  Key encoding format: hex, base64, base64url (default: hex)
//   --name, -n      Base name for key files (default: neptune)
func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringVarP(&keygenOutputDir, "output", "o", ".", "Output directory for key files")
	keygenCmd.Flags().StringVarP(&keygenEncoding, "encoding", "e", "hex", "Encoding format (hex, base64, base64url)")
	keygenCmd.Flags().StringVarP(&keygenName, "name", "n", "neptune", "Base name for key files")
}
