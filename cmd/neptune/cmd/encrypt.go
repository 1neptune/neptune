package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	neptuneCrypto "neptune/pkg/crypto"
	neptuneCurve25519 "neptune/pkg/curve25519"
	"neptune/internal/utils"
)

var (
	encryptInputFile       string
	encryptOutputFile      string
	encryptText            string
	encryptPublicKey       string
	encryptPrivateKey      string
	encryptEncoding        string
	encryptKeyEncoding     string
	encryptForce           bool
	encryptForceOverride   bool
	encryptRemoveSource    bool
	encryptRecursive       bool
	encryptInclude         []string
	encryptExclude         []string
	encryptTimeout         int
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file, text or directory",
	Long: `Encrypt a file, text or directory using Curve25519 key exchange and Sosemanuk stream cipher.

You need to provide:
  - Your private key (for authentication)
  - Recipient's public key (for encryption)

The encrypted data includes metadata (version, sender's public key, nonce) and can only be decrypted
by the recipient using their private key.

By default, Neptune prevents duplicate encryption by detecting .ntp files and encrypted file headers.
Use --force-override to force encryption of already encrypted files.

Examples:
  # Encrypt a file
  neptune encrypt --input plaintext.txt --output encrypted.bin --public-key recipient_public.key --private-key my_private.key

  # Encrypt text directly
  neptune encrypt --text "secret message" --public-key recipient_public.key --private-key my_private.key

  # Encrypt with base64 encoded keys
  neptune encrypt --input data.txt --output encrypted.bin --public-key recipient.key --private-key my.key --key-encoding base64

  # Encrypt and remove source file
  neptune encrypt --input secret.txt --output secret.ntp --public-key recipient.key --private-key my.key --remove-source

  # Encrypt a directory recursively
  neptune encrypt --input documents/ --output encrypted/ --public-key recipient.key --private-key my.key --recursive

  # Encrypt directory with file filtering
  neptune encrypt --input documents/ --output encrypted/ --public-key recipient.key --private-key my.key --recursive --include "*.pdf" --exclude "*.tmp"

  # Force encryption of already encrypted file
  neptune encrypt --input encrypted.ntp --output reencrypted.ntp --public-key recipient.key --private-key my.key --force-override`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate inputs
		if encryptInputFile == "" && encryptText == "" {
			return utils.NewMissingInputError("input or text")
		}
		if encryptPublicKey == "" {
			return utils.NewMissingInputError("public-key")
		}
		if encryptPrivateKey == "" {
			return utils.NewMissingInputError("private-key")
		}

		// --input 参数只能是本地文件路径，不能是 URL
		if encryptInputFile != "" && utils.IsHTTPURL(encryptInputFile) {
			return &utils.NeptuneError{
				Code:       utils.ErrCodeInvalidInput,
				Message:    "--input 参数不支持 URL",
				Suggestion: "请使用 download 命令下载远程资源，或使用本地文件路径",
			}
		}

		// Set timeout
		timeout := time.Duration(encryptTimeout) * time.Second
		if timeout <= 0 {
			timeout = utils.DefaultHTTPTimeout
		}

		// Parse encoding type for keys
		keyEncoding, err := utils.ParseEncodingType(encryptKeyEncoding)
		if err != nil {
			return err
		}

		// Load sender's private key (纯内存加载)
		var senderKeyPair *neptuneCurve25519.KeyPair
		if utils.IsHTTPURL(encryptPrivateKey) {
			utils.PrintInfo("正在从远程加载私钥到内存: %s", encryptPrivateKey)
			keyData, err := utils.DownloadBytes(encryptPrivateKey, timeout)
			if err != nil {
				return err
			}
			senderKeyPair, err = neptuneCurve25519.LoadKeyPairFromBytes(keyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPrivateKey, err)
			}
		} else {
			if err := utils.ValidateFilePath(encryptPrivateKey); err != nil {
				return err
			}
			senderKeyPair, err = neptuneCurve25519.LoadKeyPairFromFile(encryptPrivateKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPrivateKey, err)
			}
		}

		// Load recipient's public key (纯内存加载)
		var recipientPublicKey [neptuneCurve25519.KeySize]byte
		if utils.IsHTTPURL(encryptPublicKey) {
			utils.PrintInfo("正在从远程加载公钥到内存: %s", encryptPublicKey)
			keyData, err := utils.DownloadBytes(encryptPublicKey, timeout)
			if err != nil {
				return err
			}
			recipientPublicKey, err = neptuneCurve25519.LoadPublicKeyFromBytes(keyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPublicKey, err)
			}
		} else {
			if err := utils.ValidateFilePath(encryptPublicKey); err != nil {
				return err
			}
			recipientPublicKey, err = neptuneCurve25519.LoadPublicKeyFromFile(encryptPublicKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPublicKey, err)
			}
		}

		// Check if input is a directory
		if encryptInputFile != "" {
			info, err := os.Stat(encryptInputFile)
			if err != nil {
				return utils.NewFileReadError(encryptInputFile, err)
			}

			if info.IsDir() {
				if !encryptRecursive {
					return utils.NewInvalidInputError("input", "输入是目录，请使用 --recursive 选项")
				}
				return encryptDirectory(encryptInputFile, encryptOutputFile, senderKeyPair, recipientPublicKey)
			}
		}

		// Handle single file or text encryption
		return encryptSingleFileOrText(encryptInputFile, encryptOutputFile, encryptText, senderKeyPair, recipientPublicKey)
	},
}

func encryptSingleFileOrText(inputFile, outputFile, text string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// Read input data
	var plaintext []byte
	if inputFile != "" {
		// Validate input file
		if err := utils.ValidateFileForRead(inputFile); err != nil {
			return err
		}

		// Check if file is already encrypted
		if err := utils.ValidateNotEncrypted(inputFile, encryptForceOverride); err != nil {
			return err
		}

		data, err := os.ReadFile(inputFile)
		if err != nil {
			return utils.NewFileReadError(inputFile, err)
		}
		plaintext = data
	} else {
		plaintext = []byte(text)
	}

	// Encrypt the data
	encryptedData, err := neptuneCrypto.EncryptWithKeyPair(plaintext, senderKeyPair, recipientPublicKey)
	if err != nil {
		return utils.NewEncryptError(err)
	}

	// Serialize encrypted data
	ciphertext := encryptedData.Serialize()

	// Write output
	if outputFile != "" {
		// Validate output file
		if err := utils.ValidateFileForWrite(outputFile, encryptForce); err != nil {
			return err
		}
		if err := os.WriteFile(outputFile, ciphertext, 0644); err != nil {
			return utils.NewFileWriteError(outputFile, err)
		}

		utils.PrintSuccess("数据加密成功!")
		inputDesc := inputFile
		if inputDesc == "" {
			inputDesc = "文本"
		}
		utils.PrintInfo("输入: %s (%s)", inputDesc, utils.FormatFileSize(int64(len(plaintext))))
		utils.PrintInfo("输出: %s (%s)", outputFile, utils.FormatFileSize(int64(len(ciphertext))))
		utils.PrintWarning("请妥善保管加密文件和密钥")

		// Remove source file if requested
		if encryptRemoveSource && inputFile != "" {
			if !encryptForce {
				utils.PrintQuestion("确定要删除源文件 %s 吗? (y/N)", inputFile)
				var response string
				fmt.Scanln(&response)
				if response != "y" && response != "Y" {
					utils.PrintInfo("保留源文件")
				} else {
					if err := os.Remove(inputFile); err != nil {
						return utils.NewFileDeleteError(inputFile, err)
					}
					utils.PrintSuccess("源文件已删除: %s", inputFile)
				}
			} else {
				if err := os.Remove(inputFile); err != nil {
					return utils.NewFileDeleteError(inputFile, err)
				}
				utils.PrintSuccess("源文件已删除: %s", inputFile)
			}
		}
	} else {
		// Output to stdout
		if _, err := io.WriteString(os.Stdout, string(ciphertext)); err != nil {
			return utils.NewFileWriteError("stdout", err)
		}
	}

	return nil
}

// encryptDataToFile encrypts byte data and writes to output file
func encryptDataToFile(data []byte, outputFile string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// Encrypt the data using KeyPair
	encryptedData, err := neptuneCrypto.EncryptWithKeyPair(data, senderKeyPair, recipientPublicKey)
	if err != nil {
		return err
	}

	// Serialize encrypted data to bytes
	ciphertext := encryptedData.Serialize()

	// Write to output file
	if err := utils.EnsureParentDirectory(outputFile); err != nil {
		return err
	}

	if err := os.WriteFile(outputFile, ciphertext, 0644); err != nil {
		return utils.NewFileWriteError(outputFile, err)
	}

	utils.PrintSuccess("数据加密成功!")
	utils.PrintInfo("输入: 远程数据 (%s)", utils.FormatFileSize(int64(len(data))))
	utils.PrintInfo("输出: %s (%s)", outputFile, utils.FormatFileSize(int64(len(ciphertext))))
	utils.PrintWarning("请妥善保管加密文件和密钥")

	return nil
}

func encryptDirectory(inputDir, outputDir string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// Find all files to encrypt
	files, err := utils.FindFilesRecursively(inputDir, encryptInclude, encryptExclude)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return utils.NewInvalidInputError("input", "目录中没有找到匹配的文件")
	}

	// Create output directory if it doesn't exist
	if err := utils.EnsureDirectory(outputDir); err != nil {
		return err
	}

	utils.PrintInfo("找到 %d 个文件需要加密", len(files))
	successCount := 0
	failedCount := 0
	skippedCount := 0

	for _, filePath := range files {
		// Check if file is already encrypted
		isEncrypted, err := utils.IsNeptuneEncryptedFile(filePath)
		if err != nil {
			utils.PrintError("无法检查文件状态: %s", filePath)
			failedCount++
			continue
		}

		if isEncrypted {
			if encryptForceOverride {
				utils.PrintWarning("警告: 文件已加密，将覆盖: %s", filePath)
			} else {
				utils.PrintInfo("跳过已加密文件: %s", filePath)
				skippedCount++
				continue
			}
		}

		// Get relative path from input directory
		relPath, err := utils.GetRelativePathFromBase(inputDir, filePath)
		if err != nil {
			utils.PrintError("无法获取相对路径: %s", filePath)
			failedCount++
			continue
		}

		// Create output file path
		outputFilePath := filepath.Join(outputDir, relPath+".ntp")

		// Ensure parent directory exists
		if err := utils.EnsureParentDirectory(outputFilePath); err != nil {
			utils.PrintError("无法创建目录: %s", filepath.Dir(outputFilePath))
			failedCount++
			continue
		}

		// Read file content
		plaintext, err := os.ReadFile(filePath)
		if err != nil {
			utils.PrintError("无法读取文件: %s", filePath)
			failedCount++
			continue
		}

		// Encrypt the data
		encryptedData, err := neptuneCrypto.EncryptWithKeyPair(plaintext, senderKeyPair, recipientPublicKey)
		if err != nil {
			utils.PrintError("加密失败: %s", filePath)
			failedCount++
			continue
		}

		// Serialize and write output
		ciphertext := encryptedData.Serialize()
		if err := os.WriteFile(outputFilePath, ciphertext, 0644); err != nil {
			utils.PrintError("写入文件失败: %s", outputFilePath)
			failedCount++
			continue
		}

		// Remove source file if requested
		if encryptRemoveSource {
			if encryptForce || confirmRemoveFile(filePath) {
				if err := os.Remove(filePath); err != nil {
					utils.PrintWarning("删除源文件失败: %s", filePath)
				} else {
					utils.PrintSuccess("加密并删除: %s", filePath)
				}
			} else {
				utils.PrintSuccess("加密完成: %s", filePath)
			}
		} else {
			utils.PrintSuccess("加密完成: %s", filePath)
		}

		successCount++
	}

	utils.PrintInfo("加密完成: %d 成功, %d 失败, %d 跳过(已加密)", successCount, failedCount, skippedCount)

	if failedCount > 0 {
		return fmt.Errorf("部分文件加密失败")
	}

	return nil
}

func confirmRemoveFile(filePath string) bool {
	utils.PrintQuestion("确定要删除源文件 %s 吗? (y/N)", filePath)
	var response string
	fmt.Scanln(&response)
	return response == "y" || response == "Y"
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&encryptInputFile, "input", "i", "", "Input file or directory to encrypt (local only)")
	encryptCmd.Flags().StringVarP(&encryptOutputFile, "output", "o", "", "Output file or directory for encrypted data (default: stdout)")
	encryptCmd.Flags().StringVarP(&encryptText, "text", "t", "", "Text to encrypt (alternative to --input)")
	encryptCmd.Flags().StringVarP(&encryptPublicKey, "public-key", "p", "", "Recipient's public key file or URL")
	encryptCmd.Flags().StringVarP(&encryptPrivateKey, "private-key", "k", "", "Your private key file or URL")
	encryptCmd.Flags().StringVarP(&encryptKeyEncoding, "key-encoding", "e", "hex", "Encoding format for keys (hex, base64, base64url)")
	encryptCmd.Flags().BoolVarP(&encryptForce, "force", "f", false, "Force overwrite existing output file")
	encryptCmd.Flags().BoolVar(&encryptForceOverride, "force-override", false, "Force encryption of already encrypted files")
	encryptCmd.Flags().BoolVarP(&encryptRemoveSource, "remove-source", "r", false, "Remove source file after successful encryption")
	encryptCmd.Flags().BoolVarP(&encryptRecursive, "recursive", "R", false, "Recursively encrypt all files in a directory")
	encryptCmd.Flags().StringArrayVar(&encryptInclude, "include", []string{}, "Include files matching pattern (e.g., *.pdf)")
	encryptCmd.Flags().StringArrayVar(&encryptExclude, "exclude", []string{}, "Exclude files matching pattern (e.g., *.tmp)")
	encryptCmd.Flags().IntVar(&encryptTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")

	encryptCmd.MarkFlagRequired("public-key")
	encryptCmd.MarkFlagRequired("private-key")
}