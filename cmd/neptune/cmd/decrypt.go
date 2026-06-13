package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	neptuneCrypto "neptune/pkg/crypto"
	neptuneCurve25519 "neptune/pkg/curve25519"
	"neptune/internal/utils"
)

var (
	decryptInputFile     string
	decryptOutputFile    string
	decryptPrivateKey    string
	decryptKeyEncoding   string
	decryptForce         bool
	decryptRecursive     bool
	decryptInclude       []string
	decryptExclude       []string
	decryptTimeout       int
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file or directory",
	Long: `Decrypt a file, directory or text that was encrypted with your public key.

You need to provide:
  - Your private key (for decryption)
  - The encrypted file, directory or data

The decryption process:
  1. Reads the encrypted data format (version, sender's public key, nonce, ciphertext)
  2. Computes shared secret using ECDH with sender's public key and your private key
  3. Derives decryption key using HKDF-SHA256
  4. Decrypts data using Sosemanuk stream cipher

Examples:
  # Decrypt a file
  neptune decrypt --input encrypted.bin --output plaintext.txt --private-key my_private.key

  # Decrypt and output to stdout
  neptune decrypt --input encrypted.bin --private-key my_private.key

  # Decrypt with base64 encoded keys
  neptune decrypt --input encrypted.bin --output plaintext.txt --private-key my.key --key-encoding base64

  # Decrypt a directory recursively
  neptune decrypt --input encrypted/ --output decrypted/ --private-key my.key --recursive

  # Decrypt directory with file filtering
  neptune decrypt --input encrypted/ --output decrypted/ --private-key my.key --recursive --include "*.ntp"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate inputs
		if decryptInputFile == "" {
			return utils.NewMissingInputError("input")
		}
		if decryptPrivateKey == "" {
			return utils.NewMissingInputError("private-key")
		}

		// --input 参数只能是本地文件路径，不能是 URL
		if utils.IsHTTPURL(decryptInputFile) {
			return &utils.NeptuneError{
				Code:   utils.ErrCodeInvalidInput,
				Message: "--input 参数不支持 URL",
				Suggestion: "请使用本地文件路径",
			}
		}

		// Set timeout
		timeout := time.Duration(decryptTimeout) * time.Second
		if timeout <= 0 {
			timeout = utils.DefaultHTTPTimeout
		}

		// Parse encoding type for keys
		keyEncoding, err := utils.ParseEncodingType(decryptKeyEncoding)
		if err != nil {
			return err
		}

		// Load recipient's private key (纯内存加载)
		var recipientKeyPair *neptuneCurve25519.KeyPair
		if utils.IsHTTPURL(decryptPrivateKey) {
			utils.PrintInfo("正在从远程加载私钥到内存: %s", decryptPrivateKey)
			keyData, err := utils.DownloadBytes(decryptPrivateKey, timeout)
			if err != nil {
				return err
			}
			recipientKeyPair, err = neptuneCurve25519.LoadKeyPairFromBytes(keyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(decryptPrivateKey, err)
			}
		} else {
			if err := utils.ValidateFilePath(decryptPrivateKey); err != nil {
				return err
			}
			recipientKeyPair, err = neptuneCurve25519.LoadKeyPairFromFile(decryptPrivateKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(decryptPrivateKey, err)
			}
		}

		// Check if input is a directory
		info, err := os.Stat(decryptInputFile)
		if err != nil {
			return utils.NewFileReadError(decryptInputFile, err)
		}

		if info.IsDir() {
			if !decryptRecursive {
				return utils.NewInvalidInputError("input", "输入是目录，请使用 --recursive 选项")
			}
			return decryptDirectory(decryptInputFile, decryptOutputFile, recipientKeyPair)
		}

		// Handle single file decryption
		return decryptSingleFile(decryptInputFile, decryptOutputFile, recipientKeyPair)
	},
}

func decryptSingleFile(inputFile, outputFile string, recipientKeyPair *neptuneCurve25519.KeyPair) error {
	// Validate input file
	if err := utils.ValidateFileForRead(inputFile); err != nil {
		return err
	}

	// Read encrypted data
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		return utils.NewFileReadError(inputFile, err)
	}

	// Deserialize encrypted data
	encryptedData, err := neptuneCrypto.DeserializeEncryptedData(ciphertext)
	if err != nil {
		return utils.NewDecryptError(err)
	}

	// Decrypt the data
	plaintext, err := neptuneCrypto.DecryptWithKeyPair(encryptedData, recipientKeyPair)
	if err != nil {
		return utils.NewDecryptError(err)
	}

	// Write output
	if outputFile != "" {
		// Validate output file
		if err := utils.ValidateFileForWrite(outputFile, decryptForce); err != nil {
			return err
		}
		if err := os.WriteFile(outputFile, plaintext, 0644); err != nil {
			return utils.NewFileWriteError(outputFile, err)
		}

		utils.PrintSuccess("数据解密成功!")
		utils.PrintInfo("输入: %s (%s)", inputFile, utils.FormatFileSize(int64(len(ciphertext))))
		utils.PrintInfo("输出: %s (%s)", outputFile, utils.FormatFileSize(int64(len(plaintext))))
	} else {
		// Output to stdout
		if _, err := os.Stdout.Write(plaintext); err != nil {
			return utils.NewFileWriteError("stdout", err)
		}
	}

	return nil
}

func decryptDirectory(inputDir, outputDir string, recipientKeyPair *neptuneCurve25519.KeyPair) error {
	// Find all encrypted files (.ntp files)
	// Build include patterns to include .ntp files by default
	includePatterns := decryptInclude
	if len(includePatterns) == 0 {
		includePatterns = []string{"*.ntp"}
	}

	files, err := utils.FindFilesRecursively(inputDir, includePatterns, decryptExclude)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return utils.NewInvalidInputError("input", "目录中没有找到匹配的加密文件")
	}

	// Create output directory if it doesn't exist
	if err := utils.EnsureDirectory(outputDir); err != nil {
		return err
	}

	utils.PrintInfo("找到 %d 个文件需要解密", len(files))
	successCount := 0
	failedCount := 0

	for _, filePath := range files {
		// Get relative path from input directory
		relPath, err := utils.GetRelativePathFromBase(inputDir, filePath)
		if err != nil {
			utils.PrintError("无法获取相对路径: %s", filePath)
			failedCount++
			continue
		}

		// Remove .ntp extension from output path
		outputFilePath := filepath.Join(outputDir, strings.TrimSuffix(relPath, ".ntp"))

		// Ensure parent directory exists
		if err := utils.EnsureParentDirectory(outputFilePath); err != nil {
			utils.PrintError("无法创建目录: %s", filepath.Dir(outputFilePath))
			failedCount++
			continue
		}

		// Read encrypted data
		ciphertext, err := os.ReadFile(filePath)
		if err != nil {
			utils.PrintError("无法读取文件: %s", filePath)
			failedCount++
			continue
		}

		// Deserialize encrypted data
		encryptedData, err := neptuneCrypto.DeserializeEncryptedData(ciphertext)
		if err != nil {
			utils.PrintError("无效的加密数据: %s", filePath)
			failedCount++
			continue
		}

		// Decrypt the data
		plaintext, err := neptuneCrypto.DecryptWithKeyPair(encryptedData, recipientKeyPair)
		if err != nil {
			utils.PrintError("解密失败: %s", filePath)
			failedCount++
			continue
		}

		// Write output
		if err := os.WriteFile(outputFilePath, plaintext, 0644); err != nil {
			utils.PrintError("写入文件失败: %s", outputFilePath)
			failedCount++
			continue
		}

		utils.PrintSuccess("解密完成: %s -> %s", filePath, outputFilePath)
		successCount++
	}

	utils.PrintInfo("解密完成: %d 成功, %d 失败", successCount, failedCount)

	if failedCount > 0 {
		return fmt.Errorf("部分文件解密失败")
	}

	return nil
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringVarP(&decryptInputFile, "input", "i", "", "Input file or directory to decrypt (required)")
	decryptCmd.Flags().StringVarP(&decryptOutputFile, "output", "o", "", "Output file or directory for decrypted data (default: stdout)")
	decryptCmd.Flags().StringVarP(&decryptPrivateKey, "private-key", "k", "", "Your private key file (required)")
	decryptCmd.Flags().StringVarP(&decryptKeyEncoding, "key-encoding", "e", "hex", "Encoding format for keys (hex, base64, base64url)")
	decryptCmd.Flags().BoolVarP(&decryptForce, "force", "f", false, "Force overwrite existing output file")
	decryptCmd.Flags().BoolVarP(&decryptRecursive, "recursive", "R", false, "Recursively decrypt all files in a directory")
	decryptCmd.Flags().StringArrayVar(&decryptInclude, "include", []string{}, "Include files matching pattern (default: *.ntp)")
	decryptCmd.Flags().StringArrayVar(&decryptExclude, "exclude", []string{}, "Exclude files matching pattern")
	decryptCmd.Flags().IntVar(&decryptTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")

	decryptCmd.MarkFlagRequired("input")
	decryptCmd.MarkFlagRequired("private-key")
}