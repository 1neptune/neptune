// Package cmd provides the command-line interface commands for the neptune tool.
// This file implements the "decrypt" command, which decrypts files and directories
// that were encrypted using the neptune encryption tool. It supports single-file
// decryption, directory decryption, and disk-scan mode for decrypting files across
// all available disks.
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
	"neptune/pkg/sosemanuk"
	"neptune/internal/utils"
)

var (
	// decryptInputFile specifies the path to the input file or directory to decrypt.
	// When empty, the command operates in disk-scan mode.
	decryptInputFile string

	// decryptOutputFile specifies the output directory for decrypted data.
	// If empty, defaults to the same location as the input.
	decryptOutputFile string

	// decryptPrivateKey specifies the path or URL to the recipient's private key file
	// used for decryption. This can be a local file path or an HTTP/HTTPS URL.
	decryptPrivateKey string

	// decryptKeyEncoding specifies the encoding format of the private key.
	// Valid values are "hex", "base64", and "base64url". Defaults to "hex".
	decryptKeyEncoding string

	// decryptInclude is a list of file patterns to include when decrypting directories.
	// Defaults to "*.ntp" when not specified.
	decryptInclude []string

	// decryptExclude is a list of file patterns to exclude when decrypting directories.
	decryptExclude []string

	// decryptTimeout specifies the HTTP request timeout in seconds for downloading
	// remote keys. Defaults to 30 seconds.
	decryptTimeout int

	// decryptChunkSize specifies the buffer size for streaming decryption.
	// Accepts human-readable values like "64KB", "1MB", "4MB". Defaults to "64KB".
	decryptChunkSize string // buffer size for streaming decryption

	// decryptParallel specifies the number of parallel decryption threads
	// for directory and disk-scan mode. Defaults to 1.
	decryptParallel int // number of parallel processes
)

// decryptCmd is the cobra command for decrypting files and directories.
// It supports single-file decryption, directory decryption with optional
// include/exclude patterns, and disk-scan mode for decrypting files
// across all available disks.
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file or directory",
	Long: `Decrypt a file or directory that was encrypted with your public key.

You need to provide:
  - Your private key (for decryption)
  - The encrypted file or directory

The decryption process:
  1. Reads the encrypted data format (version, sender's public key, nonce, ciphertext)
  2. Computes shared secret using ECDH with sender's public key and your private key
  3. Derives decryption key using HKDF-SHA256
  4. Decrypts data using Sosemanuk stream cipher

Auto-enabled behaviors:
  - Force overwrite: existing output files are always overwritten
  - Remove source: encrypted source file is always removed after successful decryption
  - Recursive: directories are always processed recursively
  - Already-decrypted detection: non-encrypted files are skipped

Examples:
  # Decrypt a file (output to same directory as input)
  neptune decrypt --input document.pdf.ntp --private-key my.key

  # Decrypt a file to different directory
  neptune decrypt --input document.pdf.ntp --output ./decrypted --private-key my.key

  # Decrypt a directory (output to same directory)
  neptune decrypt --input ./encrypted --private-key my.key

  # Decrypt a directory to different directory
  neptune decrypt --input ./encrypted --output ./decrypted --private-key my.key

  # Decrypt only .ntp files in a directory
  neptune decrypt --input ./encrypted --include "*.ntp" --private-key my.key

  # Decrypt with remote key from HTTPS URL
  neptune decrypt --input data.ntp --private-key https://server.com/priv.key

  # Disk-scan mode: decrypt all .ntp files across all disks
  neptune decrypt --include "*.ntp" --private-key my.key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate that private key is provided
		if decryptPrivateKey == "" {
			return utils.NewMissingInputError("private-key")
		}

		// Determine if we're in disk-scan mode (no input file specified)
		diskScanMode := decryptInputFile == ""

		// Apply default settings optimized for disk-scan mode
		if diskScanMode {
			// Require include patterns for disk-scan mode to avoid decrypting everything
			if len(decryptInclude) == 0 {
				return &utils.NeptuneError{
					Code:       utils.ErrCodeInvalidInput,
					Message:    "--include parameter is required when --input is not specified",
					Suggestion: "use --include flag to specify file patterns (e.g., --include \"*.ntp\")",
				}
			}

			// Set defaults for disk-scan mode: timeout, larger chunks, more parallelism
			if decryptTimeout <= 0 {
				decryptTimeout = 30
			}
			if decryptChunkSize == "" || decryptChunkSize == "64KB" {
				decryptChunkSize = "4MB"
			}
			if decryptParallel == 0 || decryptParallel == 1 {
				decryptParallel = 8
			}
		}

		// Validate input is provided when not in disk-scan mode
		if !diskScanMode && decryptInputFile == "" {
			return utils.NewMissingInputError("input")
		}

		// Reject URL inputs for --input (only local files supported)
		if decryptInputFile != "" && utils.IsHTTPURL(decryptInputFile) {
			return &utils.NeptuneError{
				Code:       utils.ErrCodeInvalidInput,
				Message:    "--input parameter does not support URL",
				Suggestion: "please use a local file path",
			}
		}

		// Parse and validate chunk size from human-readable format
		chunkSize, err := utils.ParseChunkSize(decryptChunkSize)
		if err != nil {
			return err
		}
		if err := utils.ValidateChunkSize(chunkSize); err != nil {
			return err
		}

		// Validate parallel count is within acceptable range
		if decryptParallel < 1 {
			return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", decryptParallel), "must be greater than or equal to 1")
		}
		if decryptParallel > 10 {
			utils.PrintWarning(" %d，greater than 10 to avoid resource exhaustion", decryptParallel)
		}

		// Configure timeout duration for HTTP requests
		timeout := time.Duration(decryptTimeout) * time.Second
		if timeout <= 0 {
			timeout = utils.DefaultHTTPTimeout
		}

		// Parse the key encoding type (hex, base64, base64url)
		keyEncoding, err := utils.ParseEncodingType(decryptKeyEncoding)
		if err != nil {
			return err
		}

		// Load the recipient's private key pair, either from remote URL or local file
		var recipientKeyPair *neptuneCurve25519.KeyPair
		var keyData []byte
		if utils.IsHTTPURL(decryptPrivateKey) {
			// Download private key from remote URL into memory
			utils.PrintInfo("Loading private key from remote to memory: %s", decryptPrivateKey)
			keyData, err = utils.DownloadBytes(decryptPrivateKey, timeout)
			if err != nil {
				return err
			}
			recipientKeyPair, err = neptuneCurve25519.LoadKeyPairFromBytes(keyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(decryptPrivateKey, err)
			}
			// Securely clear downloaded key data from memory after loading
			utils.PrintInfo("[Memory] Clearing downloaded private key data (%d bytes)...", len(keyData))
			utils.SecureZeroMemory(keyData)
			utils.PrintSuccess("[Memory] Private key data cleared from memory")
		} else {
			// Load private key from local file
			if err := utils.ValidateFilePath(decryptPrivateKey); err != nil {
				return err
			}
			recipientKeyPair, err = neptuneCurve25519.LoadKeyPairFromFile(decryptPrivateKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(decryptPrivateKey, err)
			}
		}

		// Securely wipe the private key URL/path from memory
		utils.PrintInfo("[Memory] Clearing private key URL...")
		utils.SecureWipeString(&decryptPrivateKey)
		utils.PrintSuccess("[Memory] Private key URL cleared from memory")

		// Dispatch to appropriate decryption mode
		if diskScanMode {
			return decryptAllDisks(recipientKeyPair, chunkSize, decryptParallel)
		}

		// Determine if input is a file or directory
		info, err := os.Stat(decryptInputFile)
		if err != nil {
			return utils.NewFileReadError(decryptInputFile, err)
		}

		// Handle directory decryption
		if info.IsDir() {
			// Default output to input directory if not specified
			if decryptOutputFile == "" {
				decryptOutputFile = decryptInputFile
			} else {
				// Validate or create output directory
				outputInfo, err := os.Stat(decryptOutputFile)
				if err != nil {
					// Output directory does not exist, create it
					if err := os.MkdirAll(decryptOutputFile, 0755); err != nil {
						return utils.NewInvalidInputError("output", fmt.Sprintf("failed to create output directory: %s", decryptOutputFile))
					}
				} else if !outputInfo.IsDir() {
					return utils.NewInvalidInputError("output", "output must be a directory when input is a directory")
				}
			}
			return decryptDirectory(decryptInputFile, decryptOutputFile, recipientKeyPair, chunkSize, decryptParallel)
		}

		// Handle single file decryption: output must be a directory
		if decryptOutputFile == "" {
			decryptOutputFile = filepath.Dir(decryptInputFile)
		} else {
			// Validate or create output directory
			outputInfo, err := os.Stat(decryptOutputFile)
			if err != nil {
				// Output directory does not exist, create it
				if err := os.MkdirAll(decryptOutputFile, 0755); err != nil {
					return utils.NewInvalidInputError("output", fmt.Sprintf("failed to create output directory: %s", decryptOutputFile))
				}
			} else if !outputInfo.IsDir() {
				return utils.NewInvalidInputError("output", "output must be a directory, not a file name")
			}
		}
		return decryptSingleFile(decryptInputFile, decryptOutputFile, recipientKeyPair, chunkSize)
	},
}

// decryptSingleFile decrypts a single encrypted file and writes the decrypted
// output to the specified directory. The output filename is derived by removing
// the ".ntp" suffix from the input filename. After successful decryption, the
// source encrypted file is removed.
//
// Parameters:
//   - inputFile: path to the encrypted input file (must have .ntp extension)
//   - outputFile: destination directory for the decrypted output file
//   - recipientKeyPair: the recipient's Curve25519 key pair used for decryption
//   - chunkSize: buffer size in bytes for streaming decryption
//
// Returns:
//   - error: nil if decryption succeeds, or an error describing the failure
func decryptSingleFile(inputFile, outputFile string, recipientKeyPair *neptuneCurve25519.KeyPair, chunkSize int) error {
	// Validate input file exists and is readable
	if err := utils.ValidateFileForRead(inputFile); err != nil {
		return err
	}

	// Open input file for reading
	inputFileHandle, err := os.Open(inputFile)
	if err != nil {
		return utils.NewFileReadError(inputFile, err)
	}
	defer inputFileHandle.Close()

	// Get input file size for progress reporting
	fileInfo, err := inputFileHandle.Stat()
	if err != nil {
		return utils.NewFileReadError(inputFile, err)
	}
	inputFileSize := fileInfo.Size()

	// Compute output file path by removing .ntp suffix from basename
	baseName := filepath.Base(inputFile)
	outputBaseName := strings.TrimSuffix(baseName, ".ntp")
	outputPath := filepath.Join(outputFile, outputBaseName)

	// Ensure parent directory of output file exists
	if err := utils.EnsureParentDirectory(outputPath); err != nil {
		return err
	}

	// Validate output file can be written (with force overwrite enabled)
	if err := utils.ValidateFileForWrite(outputPath, true); err != nil {
		return err
	}

	// Create output file for writing
	outputFileHandle, err := os.Create(outputPath)
	if err != nil {
		return utils.NewFileWriteError(outputPath, err)
	}
	defer outputFileHandle.Close()

	utils.PrintInfo("Decrypting file: %s (%s)", inputFile, utils.FormatFileSize(inputFileSize))

	// Perform streaming decryption with progress tracking
	totalBytes, err := decryptStreamWithProgress(inputFileHandle, outputFileHandle, recipientKeyPair, chunkSize, inputFileSize)
	if err != nil {
		return utils.NewDecryptError(err)
	}

	// Close file handles explicitly before deletion
	outputFileHandle.Close()
	inputFileHandle.Close()

	// Print decryption summary
	utils.PrintSuccess("Data decryption successful!")
	utils.PrintInfo("Input: %s (%s)", inputFile, utils.FormatFileSize(inputFileSize))
	utils.PrintInfo("Output: %s (%s)", outputPath, utils.FormatFileSize(totalBytes))

	// Remove source encrypted file after successful decryption
	if err := utils.RemoveSourceFileWithRetry(inputFile); err != nil {
		utils.PrintWarning("Failed to remove source file: %s", inputFile)
		utils.PrintWarning("Reason: %s", err.Error())
	} else {
		utils.PrintSuccess("Source file removed: %s", inputFile)
	}

	return nil
}

// decryptStreamWithProgress performs streaming decryption of data from a reader
// and writes the decrypted data to a writer. It reads the encryption header,
// computes the shared secret via ECDH, derives the decryption key using HKDF,
// initializes the Sosemanuk stream cipher, and processes data in chunks.
// All sensitive cryptographic material is securely wiped from memory after use.
//
// Parameters:
//   - reader: io.Reader providing the encrypted data stream (including header)
//   - writer: io.Writer where decrypted plaintext data will be written
//   - recipientKeyPair: the recipient's Curve25519 key pair for ECDH key exchange
//   - bufferSize: size in bytes of the read buffer for streaming
//   - totalSize: total expected size of the input (for progress indication)
//
// Returns:
//   - int64: total number of decrypted bytes written to the writer
//   - error: nil if decryption succeeds, or an error describing the failure
func decryptStreamWithProgress(reader io.Reader, writer io.Writer, recipientKeyPair *neptuneCurve25519.KeyPair, bufferSize int, totalSize int64) (int64, error) {

	// Read the fixed-size encryption header from the input stream
	header := make([]byte, neptuneCrypto.HeaderSize)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}

	// Validate encryption format version from header
	version := header[0]
	if version != neptuneCrypto.Version {
		return 0, neptuneCrypto.ErrInvalidVersion
	}

	// Extract sender's public key and nonce from the header
	var senderPubKey [neptuneCrypto.PublicKeySize]byte
	copy(senderPubKey[:], header[1:1+neptuneCrypto.PublicKeySize])
	var nonce [neptuneCrypto.NonceSize]byte
	copy(nonce[:], header[1+neptuneCrypto.PublicKeySize:])

	// Compute ECDH shared secret using recipient's private key and sender's public key
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(senderPubKey)
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}

	// Derive the symmetric encryption key using HKDF with context
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)
	decryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}

	// Initialize Sosemanuk stream cipher with derived key and nonce
	cipher, err := sosemanuk.New(decryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("create cipher failed: %w", err)
	}

	// Get a buffer from the global pool for memory efficiency
	buf := utils.GetGlobalBuffer(bufferSize)
	defer utils.PutGlobalBuffer(buf)

	// Ensure buffer is properly sized for the requested bufferSize
	if cap(buf) < bufferSize {
		buf = make([]byte, bufferSize)
	} else {
		buf = buf[:bufferSize]
	}

	utils.PrintInfo("Starting decryption...")

	// Stream decryption loop: read, decrypt, write in chunks
	var processedBytes int64
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			// Decrypt chunk in-place using XOR with Sosemanuk keystream
			cipher.XORKeyStream(buf[:n], buf[:n])

			// Write decrypted chunk to output
			nw, ew := writer.Write(buf[:n])
			if ew != nil {
				return processedBytes, fmt.Errorf("write failed: %w", ew)
			}
			if nw != n {
				return processedBytes, fmt.Errorf("incomplete write")
			}

			processedBytes += int64(n)
		}

		// Exit loop on end of file
		if err == io.EOF {
			break
		}
		// Report any read errors
		if err != nil {
			return processedBytes, fmt.Errorf("read failed: %w", err)
		}
	}

	utils.PrintSuccess("Decryption completed")

	// ========== Memory cleanup: clear sensitive data ==========

	// Clear shared secret and derived decryption key from memory
	utils.PrintInfo("[Memory] Clearing decryption key...")
	utils.SecureZeroMemory(sharedSecret[:])
	utils.SecureZeroMemory(decryptionKey)
	utils.PrintSuccess("[Memory] Decryption key cleared from memory")

	// Clear nonce from memory
	utils.PrintInfo("[Memory] Clearing nonce...")
	utils.SecureZeroMemory(nonce[:])
	utils.PrintSuccess("[Memory] Nonce cleared from memory")

	// Clear HKDF context data from memory
	utils.PrintInfo("[Memory] Clearing context data...")
	utils.SecureZeroMemory(context)
	utils.PrintSuccess("[Memory] Context data cleared from memory")

	// Clear sender's public key from memory
	utils.PrintInfo("[Memory] Clearing sender public key...")
	utils.SecureZeroMemory(senderPubKey[:])
	utils.PrintSuccess("[Memory] Sender public key cleared")

	// Clear header buffer from memory
	utils.PrintInfo("[Memory] Clearing header buffer...")
	utils.SecureZeroMemory(header)
	utils.PrintSuccess("[Memory] Header buffer cleared")

	return processedBytes, nil
}

// decryptDirectory decrypts all matching encrypted files within a directory
// tree recursively. It preserves the relative directory structure in the output
// directory. Successfully decrypted source files are removed after decryption.
//
// Parameters:
//   - inputDir: root directory to scan for encrypted files
//   - outputDir: root directory where decrypted files will be written
//   - recipientKeyPair: the recipient's Curve25519 key pair used for decryption
//   - chunkSize: buffer size in bytes for streaming decryption
//   - parallel: number of parallel decryption processes
//
// Returns:
//   - error: nil if all files decrypt successfully, or an error if any file fails
func decryptDirectory(inputDir, outputDir string, recipientKeyPair *neptuneCurve25519.KeyPair, chunkSize int, parallel int) error {

	utils.PrintInfo("Scanning directory: %s", inputDir)

	// Default include pattern to *.ntp if none specified
	includePatterns := decryptInclude
	if len(includePatterns) == 0 {
		includePatterns = []string{"*.ntp"}
	}

	// Recursively find all files matching include/exclude patterns
	files, err := utils.FindFilesRecursively(inputDir, includePatterns, decryptExclude)
	if err != nil {
		return err
	}

	// Shuffle file list for more uniform progress distribution
	utils.ShuffleStrings(files)

	// Return error if no matching files found
	if len(files) == 0 {
		return utils.NewInvalidInputError("input", "")
	}

	// Ensure output directory exists
	if err := utils.EnsureDirectory(outputDir); err != nil {
		return err
	}

	utils.PrintInfo("Found %d files to decrypt", len(files))

	// Track success/failure counts
	var successCount int32
	var failedCount int32
	var processedCount int32

	utils.PrintInfo("Decrypting directory: %s", inputDir)

	// Process each file sequentially (note: parallel param not used in this function)
	for _, filePath := range files {
		// Compute relative path to preserve directory structure
		relPath, err := utils.GetRelativePathFromBase(inputDir, filePath)
		if err != nil {
			utils.PrintError("Failed: %s", filePath)
			failedCount++
			processedCount++
			continue
		}

		// Compute output file path by removing .ntp suffix
		outputFilePath := filepath.Join(outputDir, strings.TrimSuffix(relPath, ".ntp"))

		// Ensure parent directory for output file exists
		if err := utils.EnsureParentDirectory(outputFilePath); err != nil {
			utils.PrintError("Failed to create directory: %s", filepath.Dir(outputFilePath))
			failedCount++
			processedCount++
			continue
		}

		// Get file size for progress tracking
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			utils.PrintError("Failed: %s", filePath)
			failedCount++
			processedCount++
			continue
		}

		fileSize := fileInfo.Size()

		// Skip files that have been removed since scanning
		_, err = os.Stat(filePath)
		if err != nil && os.IsNotExist(err) {
			processedCount++
			continue
		}

		utils.PrintInfo("Decrypting file: %s", filePath)

		// Open input file for reading
		inputFileHandle, err := os.Open(filePath)
		if err != nil {
			utils.PrintError("Failed: %s", filePath)
			failedCount++
			processedCount++
			continue
		}

		// Create output file for writing
		outputFileHandle, err := os.Create(outputFilePath)
		if err != nil {
			inputFileHandle.Close()
			utils.PrintError("Failed to create output file: %s", outputFilePath)
			failedCount++
			processedCount++
			continue
		}

		// Perform streaming decryption
		_, err = decryptStreamWithProgress(inputFileHandle, outputFileHandle, recipientKeyPair, chunkSize, fileSize)

		// Close file handles
		inputFileHandle.Close()
		outputFileHandle.Close()

		// Handle decryption failure by cleaning up partial output
		if err != nil {
			utils.DeleteFile(outputFilePath)
			utils.PrintError("Decryption failed: %s", filePath)
			failedCount++
			processedCount++
			continue
		}

		// On success, delete source file immediately to free disk space
		utils.PrintSuccess("Decryption completed: %s", filePath)

		if err := utils.RemoveSourceFileWithRetry(filePath); err != nil {
			utils.PrintWarning("Failed to remove source file: %s", filePath)
			utils.PrintWarning("Reason: %s", err.Error())
		} else {
			utils.PrintSuccess("Source file removed: %s", filePath)
		}

		processedCount++
		successCount++
	}

	// Print final summary
	fmt.Print("\r")
	utils.PrintInfo("Decryption completed: %d success, %d failed", successCount, failedCount)

	// Return error if any files failed to decrypt
	if failedCount > 0 {
		return fmt.Errorf("partial file decryption failure")
	}

	return nil
}

// decryptAllDisks performs disk-scan mode decryption across all available disks
// on the system. It scans each disk's top-level directories in parallel, finds
// files matching the include patterns, and decrypts them in-place. This mode is
// designed for bulk recovery scenarios where encrypted files are scattered
// across multiple disks.
//
// Parameters:
//   - recipientKeyPair: the recipient's Curve25519 key pair used for decryption
//   - chunkSize: buffer size in bytes for streaming decryption
//   - parallel: number of parallel directory scanning goroutines per disk
//
// Returns:
//   - error: nil if the overall scan completes, or an error if disk enumeration fails
func decryptAllDisks(recipientKeyPair *neptuneCurve25519.KeyPair, chunkSize int, parallel int) error {
	// Enumerate all available disks on the system (excluding C:\)
	disks, err := utils.GetAllDisks()
	if err != nil {
		return fmt.Errorf("failed to get disk list: %w", err)
	}

	// Get all user directories from C:\Users
	desktopDirs, err := utils.GetAllDesktopDirectories()
	if err != nil {
		utils.PrintWarning("Failed to get user directories: %v", err)
		desktopDirs = []string{}
	}

	// Print disk-scan mode banner and configuration
	utils.PrintWarning("==============================")
	utils.PrintWarning("DISK-SCAN DECRYPTION MODE")
	utils.PrintWarning("==============================")
	utils.PrintWarning("Number of disks to scan: %d", len(disks))
	utils.PrintWarning("Disks: %v", disks)
	utils.PrintWarning("Number of user directories: %d", len(desktopDirs))
	utils.PrintWarning("Include patterns: %v", decryptInclude)
	utils.PrintWarning("Default parameters applied:")
	utils.PrintWarning("  --force: true")
	utils.PrintWarning("  --remove-source: true")
	utils.PrintWarning("  --recursive: true")
	utils.PrintWarning("  --chunk-size: %s", decryptChunkSize)
	utils.PrintWarning("  --parallel: %d", decryptParallel)
	utils.PrintWarning("==============================")
	utils.PrintWarning("SCAN RANGE:")
	utils.PrintWarning("  - All disks except C:\\: %v", disks)
	utils.PrintWarning("  - C:\\Users\\*\\Desktop, C:\\Users\\*\\Documents, C:\\Users\\*\\Downloads")
	utils.PrintWarning("==============================")
	utils.PrintWarning("WARNING: This will decrypt files across ALL disks!")
	utils.PrintWarning("Only files matching --include patterns will be decrypted.")
	utils.PrintWarning("Original files will be removed after decryption.")
	utils.PrintWarning("==============================")

	// Track statistics across all disks using atomics for thread safety
	var totalProcessedDirs int32
	var totalSkippedDirs int32

	// Process each disk sequentially
	for diskIndex, disk := range disks {
		utils.PrintInfo("Processing disk %d/%d: %s", diskIndex+1, len(disks), disk)

		// Get top-level directories on the current disk
		topDirs, err := utils.GetTopLevelDirectories(disk)
		if err != nil {
			utils.PrintWarning("Failed to list directories on disk %s: %v", disk, err)
			continue
		}

		// Skip disks with no top-level directories
		if len(topDirs) == 0 {
			utils.PrintInfo("No directories found on disk: %s", disk)
			continue
		}

		// Shuffle directory order for more uniform load distribution
		utils.ShuffleStrings(topDirs)

		// Set up parallel processing with semaphore-based concurrency control
		var wg sync.WaitGroup
		sem := make(chan struct{}, parallel)

		// Launch goroutine for each top-level directory
		for _, dir := range topDirs {
			wg.Add(1)
			sem <- struct{}{}

			go func(dirPath string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Determine include patterns (default to *.ntp)
				includePatterns := decryptInclude
				if len(includePatterns) == 0 {
					includePatterns = []string{"*.ntp"}
				}

				// Recursively find matching files in this directory tree
				files, err := utils.FindFilesRecursively(dirPath, includePatterns, decryptExclude)
				if err != nil {
					utils.PrintWarning("Failed to scan directory: %s", dirPath)
					atomic.AddInt32(&totalProcessedDirs, 1)
					return
				}

				// Skip directories with no matching files
				if len(files) == 0 {
					atomic.AddInt32(&totalSkippedDirs, 1)
					return
				}

				// Decrypt files in this directory (in-place: same input and output)
				err = decryptDirectory(dirPath, dirPath, recipientKeyPair, chunkSize, parallel)
				if err != nil {
					utils.PrintWarning("Failed to process directory %s: %v", dirPath, err)
				}
				atomic.AddInt32(&totalProcessedDirs, 1)
			}(dir)
		}

		// Wait for all directories on this disk to complete
		wg.Wait()
	}

	// Process all user directories from C:\Users
	if len(desktopDirs) > 0 {
		utils.PrintInfo("Processing user directories from C:\\Users (%d directories)", len(desktopDirs))

		// Shuffle user directories for random processing order
		utils.ShuffleStrings(desktopDirs)

		// Set up parallel processing with semaphore-based concurrency control
		var wg sync.WaitGroup
		sem := make(chan struct{}, parallel)

		// Launch goroutine for each user directory
		for _, desktopDir := range desktopDirs {
			wg.Add(1)
			sem <- struct{}{}

			go func(dirPath string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Determine include patterns (default to *.ntp)
				includePatterns := decryptInclude
				if len(includePatterns) == 0 {
					includePatterns = []string{"*.ntp"}
				}

				// Recursively find matching files in this directory tree
				files, err := utils.FindFilesRecursively(dirPath, includePatterns, decryptExclude)
				if err != nil {
					utils.PrintWarning("Failed to scan directory: %s", dirPath)
					atomic.AddInt32(&totalProcessedDirs, 1)
					return
				}

				// Skip directories with no matching files
				if len(files) == 0 {
					atomic.AddInt32(&totalSkippedDirs, 1)
					return
				}

				// Decrypt files in this Desktop directory (in-place: same input and output)
				err = decryptDirectory(dirPath, dirPath, recipientKeyPair, chunkSize, parallel)
				if err != nil {
					utils.PrintWarning("Failed to process directory %s: %v", dirPath, err)
				}
				atomic.AddInt32(&totalProcessedDirs, 1)
			}(desktopDir)
		}

		// Wait for all Desktop directories to complete
		wg.Wait()
	}

	// Print final disk-scan summary
	utils.PrintSuccess("Disk-scan decryption completed. Processed %d directories, %d skipped (empty)", atomic.LoadInt32(&totalProcessedDirs), atomic.LoadInt32(&totalSkippedDirs))
	return nil
}

// init registers the decrypt command with the root command and sets up
// all command-line flags for the decrypt operation.
func init() {
	rootCmd.AddCommand(decryptCmd)

	// Register all command-line flags for the decrypt command
	decryptCmd.Flags().StringVarP(&decryptInputFile, "input", "i", "", "Input file or directory to decrypt (local only)")
	decryptCmd.Flags().StringVarP(&decryptOutputFile, "output", "o", "", "Output directory for decrypted data (default: input location)")
	decryptCmd.Flags().StringVarP(&decryptPrivateKey, "private-key", "k", "", "Your private key file or URL")
	decryptCmd.Flags().StringVarP(&decryptKeyEncoding, "key-encoding", "e", "hex", "Encoding format for keys (hex, base64, base64url)")
	decryptCmd.Flags().StringArrayVar(&decryptInclude, "include", []string{}, "Include files matching pattern (default: *.ntp)")
	decryptCmd.Flags().StringArrayVar(&decryptExclude, "exclude", []string{}, "Exclude files matching pattern")
	decryptCmd.Flags().IntVar(&decryptTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")
	decryptCmd.Flags().StringVar(&decryptChunkSize, "chunk-size", "64KB", "Buffer size for streaming decryption (e.g., 64KB, 1MB, 4MB)")
	decryptCmd.Flags().IntVar(&decryptParallel, "parallel", 1, "Number of parallel decryption threads (default: 1)")

	decryptCmd.MarkFlagRequired("private-key")
}
