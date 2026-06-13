package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	neptuneCurve25519 "neptune/pkg/curve25519"
	"neptune/internal/utils"
)

var (
	keygenOutputDir string
	keygenEncoding  string
	keygenName      string
)

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
		// Parse encoding type
		encoding, err := utils.ParseEncodingType(keygenEncoding)
		if err != nil {
			return err
		}

		// Generate key pair
		keyPair, err := neptuneCurve25519.GenerateKeyPair()
		if err != nil {
			return utils.NewKeyWriteError("", err)
		}

		// Create output directory if it doesn't exist
		if keygenOutputDir != "" {
			if err := utils.EnsureDirectory(keygenOutputDir); err != nil {
				return err
			}
		}

		// Determine file names
		privateKeyFile := filepath.Join(keygenOutputDir, keygenName+"_private.key")
		publicKeyFile := filepath.Join(keygenOutputDir, keygenName+"_public.key")

		// Save private key
		if err := neptuneCurve25519.SaveKeyPairToFile(keyPair, privateKeyFile, neptuneCurve25519.EncodingType(encoding)); err != nil {
			return utils.NewKeyWriteError(privateKeyFile, err)
		}

		// Save public key separately
		if err := neptuneCurve25519.SavePublicKeyToFile(keyPair.PublicKey, publicKeyFile, neptuneCurve25519.EncodingType(encoding)); err != nil {
			return utils.NewKeyWriteError(publicKeyFile, err)
		}

		// Output results
		utils.PrintSuccess("密钥对生成成功!")
		utils.PrintInfo("私钥文件: %s", privateKeyFile)
		utils.PrintInfo("公钥文件: %s", publicKeyFile)
		utils.PrintInfo("编码格式: %s", keygenEncoding)
		fmt.Printf("\n公钥内容 (可分享):\n%s\n", neptuneCurve25519.SerializePublicKey(keyPair.PublicKey, neptuneCurve25519.EncodingType(encoding)))
		utils.PrintWarning("请妥善保管私钥，切勿泄露!")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringVarP(&keygenOutputDir, "output", "o", ".", "Output directory for key files")
	keygenCmd.Flags().StringVarP(&keygenEncoding, "encoding", "e", "hex", "Encoding format (hex, base64, base64url)")
	keygenCmd.Flags().StringVarP(&keygenName, "name", "n", "neptune", "Base name for key files")
}