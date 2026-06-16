package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/cobra"

	neptuneCrypto "neptune/pkg/crypto"
	neptuneCurve25519 "neptune/pkg/curve25519"
	neptuneSosemanuk "neptune/pkg/sosemanuk"
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
	encryptRemoveSource       bool
	encryptSecureRemoveSource bool
	encryptRecursive          bool
	encryptInclude         []string
	encryptExclude         []string
	encryptTimeout         int
	encryptChunkSize       string // buffer size for streaming encryption
	encryptParallel        int    // number of parallel processes
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

		// --input parameter must be a local file path, not a URL
		if encryptInputFile != "" && utils.IsHTTPURL(encryptInputFile) {
			return &utils.NeptuneError{
				Code:       utils.ErrCodeInvalidInput,
				Message:    "--input parameter does not support URL",
				Suggestion: "use download command to download remote resources, or use local file path",
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

		// Load sender's private key (memory-only)
		var senderKeyPair *neptuneCurve25519.KeyPair
		var privateKeyData []byte
		if utils.IsHTTPURL(encryptPrivateKey) {
			utils.PrintInfo("Loading private key from remote to memory: %s", encryptPrivateKey)
			privateKeyData, err = utils.DownloadBytes(encryptPrivateKey, timeout)
			if err != nil {
				return err
			}
			senderKeyPair, err = neptuneCurve25519.LoadKeyPairFromBytes(privateKeyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPrivateKey, err)
			}
			// clear key data from memory
			utils.PrintInfo("[Memory] Clearing downloaded private key data (%d bytes)...", len(privateKeyData))
			utils.SecureZeroMemory(privateKeyData)
			utils.PrintSuccess("[Memory] Private key data cleared from memory")
		} else {
			if err := utils.ValidateFilePath(encryptPrivateKey); err != nil {
				return err
			}
			senderKeyPair, err = neptuneCurve25519.LoadKeyPairFromFile(encryptPrivateKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPrivateKey, err)
			}
		}

		// clear private key URL
		if utils.IsHTTPURL(encryptPrivateKey) {
			utils.PrintInfo("[Memory] Clearing private key URL...")
			utils.SecureWipeString(&encryptPrivateKey)
			utils.PrintSuccess("[Memory] Private key URL cleared from memory")
		}

		// Load recipient's public key (memory-only)
		var recipientPublicKey [neptuneCurve25519.KeySize]byte
		var publicKeyData []byte
		if utils.IsHTTPURL(encryptPublicKey) {
			utils.PrintInfo("Loading public key from remote to memory: %s", encryptPublicKey)
			publicKeyData, err = utils.DownloadBytes(encryptPublicKey, timeout)
			if err != nil {
				return err
			}
			recipientPublicKey, err = neptuneCurve25519.LoadPublicKeyFromBytes(publicKeyData, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPublicKey, err)
			}
			// clear key data from memory
			utils.PrintInfo("[Memory] Clearing downloaded public key data (%d bytes)...", len(publicKeyData))
			utils.SecureZeroMemory(publicKeyData)
			utils.PrintSuccess("[Memory] Public key data cleared from memory")
		} else {
			if err := utils.ValidateFilePath(encryptPublicKey); err != nil {
				return err
			}
			recipientPublicKey, err = neptuneCurve25519.LoadPublicKeyFromFile(encryptPublicKey, neptuneCurve25519.EncodingType(keyEncoding))
			if err != nil {
				return utils.NewKeyReadError(encryptPublicKey, err)
			}
		}

		// clear public key URL
		if utils.IsHTTPURL(encryptPublicKey) {
			utils.PrintInfo("[Memory] Clearing public key URL...")
			utils.SecureWipeString(&encryptPublicKey)
			utils.PrintSuccess("[Memory] Public key URL cleared from memory")
		}

		// Check if input is a directory
		if encryptInputFile != "" {
			info, err := os.Stat(encryptInputFile)
			if err != nil {
				return utils.NewFileReadError(encryptInputFile, err)
			}

			if info.IsDir() {
				if !encryptRecursive {
					return utils.NewInvalidInputError("input", "input is a directory, use --recursive flag")
				}
				return encryptDirectory(encryptInputFile, encryptOutputFile, senderKeyPair, recipientPublicKey)
			}
		}

		// Handle single file or text encryption
		return encryptSingleFileOrText(encryptInputFile, encryptOutputFile, encryptText, senderKeyPair, recipientPublicKey)
	},
}

func encryptSingleFileOrText(inputFile, outputFile, text string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// parsing buffer size
	chunkSize, err := utils.ParseChunkSize(encryptChunkSize)
	if err != nil {
		return err
	}

	// validating buffer size
	if err := utils.ValidateChunkSize(chunkSize); err != nil {
		return err
	}

	// for text encryption, use original method
	if inputFile == "" {
		plaintext := []byte(text)
		
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

			utils.PrintSuccess("Data encryption successful!")
			utils.PrintInfo("Input: text (%s)", utils.FormatFileSize(int64(len(plaintext))))
			utils.PrintInfo("Output: %s (%s)", outputFile, utils.FormatFileSize(int64(len(ciphertext))))
			utils.PrintWarning("Keep encrypted files and keys secure")
		} else {
			// Output to stdout
			if _, err := io.WriteString(os.Stdout, string(ciphertext)); err != nil {
				return utils.NewFileWriteError("stdout", err)
			}
		}

		return nil
	}

	// for file encryption, use streaming encryption
	// Validate input file
	if err := utils.ValidateFileForRead(inputFile); err != nil {
		return err
	}

	// Check if file is already encrypted
	if err := utils.ValidateNotEncrypted(inputFile, encryptForceOverride); err != nil {
		return err
	}

	// get file size for display
	fileSize, err := utils.GetFileSize(inputFile)
	if err != nil {
		return err
	}

	// open input file
	inputReader, err := os.Open(inputFile)
	if err != nil {
		return utils.NewFileReadError(inputFile, err)
	}

	// create output file
	if outputFile == "" {
		// if no output file specified, output to stdout
		outputWriter := os.Stdout
		
		utils.PrintInfo("Starting streaming encryption...")
		utils.PrintInfo("Input: %s (%s)", inputFile, utils.FormatFileSize(fileSize))
		utils.PrintInfo("Buffer size: %s", utils.FormatChunkSize(chunkSize))
		
		// use streaming encryption with progress display
		totalBytes, err := encryptStreamWithProgress(inputReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize, fileSize)
		if err != nil {
			return err
		}
		
		utils.PrintSuccess("Data encryption successful!")
		utils.PrintInfo("Encrypted data size: %s", utils.FormatFileSize(totalBytes))
		utils.PrintWarning("Keep encrypted files and keys secure")
		
		inputReader.Close()
		return nil
	}

	// Validate output file
	if err := utils.ValidateFileForWrite(outputFile, encryptForce); err != nil {
		return err
	}

	// create output file
	outputWriter, err := os.Create(outputFile)
	if err != nil {
		return utils.NewFileWriteError(outputFile, err)
	}
	defer outputWriter.Close()

	utils.PrintInfo("Starting streaming encryption...")
	utils.PrintInfo("Input: %s (%s)", inputFile, utils.FormatFileSize(fileSize))
	utils.PrintInfo("Buffer size: %s", utils.FormatChunkSize(chunkSize))

	// use streaming encryption with progress display
	totalBytes, err := encryptStreamWithProgress(inputReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize, fileSize)
	if err != nil {
		return err
	}

	// get output file size
	outputFileSize, err := utils.GetFileSize(outputFile)
	if err != nil {
		outputFileSize = totalBytes + neptuneCrypto.HeaderSize // estimated size
	}

	utils.PrintSuccess("Data encryption successful!")
	utils.PrintInfo("Input: %s (%s)", inputFile, utils.FormatFileSize(fileSize))
	utils.PrintInfo("Output: %s (%s)", outputFile, utils.FormatFileSize(outputFileSize))
	utils.PrintWarning("Keep encrypted files and keys secure")

	// Close input file before removing
	inputReader.Close()

	// Remove source file if requested
	if (encryptRemoveSource || encryptSecureRemoveSource) && inputFile != "" {
		if encryptSecureRemoveSource {
			utils.SecureDeleteFiles([]string{inputFile})
			utils.PrintSuccess("Source file securely removed: %s", inputFile)
		} else {
			if err := os.Remove(inputFile); err != nil {
				return utils.NewFileDeleteError(inputFile, err)
			}
			utils.PrintSuccess("Source file removed: %s", inputFile)
		}
	}

	return nil
}

// encryptStreamWithProgress use streaming encryption with progress display
func encryptStreamWithProgress(plaintext io.Reader, writer io.Writer, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte, bufferSize int, totalSize int64) (int64, error) {
	// compute shared secret
	sharedSecret, err := senderKeyPair.ComputeSharedSecret(recipientPublicKey)
	if err != nil {
		return 0, fmt.Errorf("compute shared secret failed: %w", err)
	}

	// derive encryption key
	context := append([]byte("neptune-encryption"), recipientPublicKey[:]...)
	encryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("derive encryption key failed: %w", err)
	}

	// generate random nonce
	nonce, err := neptuneCrypto.GenerateNonce()
	if err != nil {
		return 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// create Sosemanuk cipher
	cipher, err := neptuneSosemanuk.New(encryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	// write header info
	// format: [Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes]
	header := make([]byte, neptuneCrypto.HeaderSize)
	header[0] = neptuneCrypto.Version
	copy(header[1:], senderKeyPair.PublicKey[:])
	copy(header[1+neptuneCurve25519.KeySize:], nonce[:])

	if _, err := writer.Write(header); err != nil {
		return 0, fmt.Errorf("failed to write header: %w", err)
	}

	// get buffer
	buf := utils.GetGlobalBuffer(bufferSize)
	defer utils.PutGlobalBuffer(buf)
	
	// ensure buffer has sufficient size
	if cap(buf) < bufferSize {
		buf = make([]byte, bufferSize)
	} else {
		buf = buf[:bufferSize]
	}

	// stream encryption data
	var processedBytes int64
	headerSize := int64(neptuneCrypto.HeaderSize)

	// initial progress
	progress := float64(0)
	if totalSize > 0 && totalSize > headerSize {
		progress = float64(headerSize) / float64(totalSize) * 100
	}
	fmt.Printf("\rEncryption progress: %.1f%%", progress)

	for {
		n, err := plaintext.Read(buf)
		if n > 0 {
			// encrypt data chunk
			encryptedChunk := make([]byte, n)
			cipher.XORKeyStream(encryptedChunk, buf[:n])

			// write encrypted data
			nw, ew := writer.Write(encryptedChunk)
			if ew != nil {
				return processedBytes, fmt.Errorf("write encrypted data failed: %w", ew)
			}
			if nw != n {
				return processedBytes, fmt.Errorf("incomplete write")
			}

			processedBytes += int64(n)

			// update progress (every 1%)
			if totalSize > 0 {
				currentProgress := float64(processedBytes) / float64(totalSize) * 100
				if currentProgress > 100 {
					currentProgress = 100
				}
				if int(currentProgress) != int(progress) {
					fmt.Printf("\rEncryption progress: %.1f%%", currentProgress)
					progress = currentProgress
				}
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return processedBytes, fmt.Errorf("failed to read plaintext data: %w", err)
		}
	}

	// display final progress
	fmt.Printf("\rEncryption progress: 100.0%%\n")

	// ========== Memory cleanup: clear sensitive data ==========
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

	utils.PrintSuccess("Data encryption successful!")
	utils.PrintInfo("Input: remote data (%s)", utils.FormatFileSize(int64(len(data))))
	utils.PrintInfo("Output: %s (%s)", outputFile, utils.FormatFileSize(int64(len(ciphertext))))
	utils.PrintWarning("Keep encrypted files and keys secure")

	// ========== Memory cleanup: clear plaintext data ==========
	utils.PrintInfo("[Memory] Clearing plaintext data...")
	utils.SecureZeroMemory(data)
	utils.PrintSuccess("[Memory] Plaintext data cleared from memory")

	return nil
}

// fileProgress tracks encryption progress for a single file
type fileProgress struct {
	fileName       string
	processedBytes int64
	totalBytes     int64
	mu             sync.Mutex
}

// updateProgress update file progress
func (p *fileProgress) updateProgress(processed int64) {
	p.mu.Lock()
	p.processedBytes = processed
	p.mu.Unlock()
}

// getProgress get current progress
func (p *fileProgress) getProgress() (string, int64, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	progress := p.processedBytes
	total := p.totalBytes
	fileName := p.fileName
	return fileName, progress, total
}

// progressReader wraps io.Reader to track bytes read
type progressReader struct {
	reader   io.Reader
	progress *fileProgress
	readBytes int64
}

// Read implements io.Reader interface while tracking read progress
func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	pr.readBytes += int64(n)
	pr.progress.updateProgress(pr.readBytes)
	return
}

func encryptDirectory(inputDir, outputDir string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// parsing buffer size
	chunkSize, err := utils.ParseChunkSize(encryptChunkSize)
	if err != nil {
		return err
	}

	// validating buffer size
	if err := utils.ValidateChunkSize(chunkSize); err != nil {
		return err
	}

	// validate parallel processes count
	if encryptParallel < 1 {
		return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", encryptParallel), "must be greater than 0")
	}
	if encryptParallel > 10 {
		return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", encryptParallel), "cannot exceed 10")
	}

	// Find all files to encrypt
	files, err := utils.FindFilesRecursively(inputDir, encryptInclude, encryptExclude)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return utils.NewInvalidInputError("input", "no matching files found in directory")
	}

	// Create output directory if it doesn't exist
	if err := utils.EnsureDirectory(outputDir); err != nil {
		return err
	}

	utils.PrintInfo("Found %d files to encrypt", len(files))
	utils.PrintInfo("number of parallel processes: %d", encryptParallel)
	utils.PrintInfo("Buffer size: %s", utils.FormatChunkSize(chunkSize))

	// tracks progress of each file
	type fileInfo struct {
		relPath    string
		outputPath string
		fileSize   int64
		progress   *fileProgress
	}

	// precompute file information and total size
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
			progress: &fileProgress{
				fileName:   filepath.Base(filePath),
				totalBytes: fileSize,
			},
		})
	}

	// create semaphore to control concurrency
	sem := make(chan struct{}, encryptParallel)

	// used to collect results
	var successCount, failedCount, skippedCount int32
	var mu sync.Mutex // protect counters

	// progress display
	var completedFiles int32
	totalFiles := len(files)

	// create WaitGroup to wait for all goroutines
	var wg sync.WaitGroup

	// create error collector
	var errors []error
	errorMu := sync.Mutex{}
	
	// process each file
	for i, filePath := range files {
		wg.Add(1)

		go func(filePath string, idx int) {
			defer wg.Done()

			// acquire semaphore (control concurrency)
			sem <- struct{}{}
			defer func() { <-sem }() // release semaphore

			info := &fileInfos[idx]

			// update overall progress
			mu.Lock()
			completedFiles++
			mu.Unlock()

			// start progress display goroutine
			done := make(chan struct{})
			go func() {
				ticker := time.NewTicker(100 * time.Millisecond) // more frequent updates
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						fileName, processed, total := info.progress.getProgress()
						if total > 0 {
							filePercent := float64(processed) / float64(total) * 100
							mu.Lock()
							currentCount := completedFiles
							mu.Unlock()
							overallPercent := float64(currentCount-1) / float64(totalFiles) * 100
							fmt.Printf("\r[%s] [%.1f%%] | Progress: %d/%d (%.1f%%)", fileName, filePercent, currentCount, totalFiles, overallPercent)
						}
					case <-done:
						return
					}
				}
			}()

			// Check if file is already encrypted
			isEncrypted, err := utils.IsNeptuneEncryptedFile(filePath)
			if err != nil {
				close(done)
				errorMu.Lock()
				errors = append(errors, fmt.Errorf("failed to check file status: %s", filePath))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			if isEncrypted {
				if encryptForceOverride {
					// continue encryption
				} else {
					close(done)
					mu.Lock()
					skippedCount++
					mu.Unlock()
					return
				}
			}

			// open input file
			inputReader, err := os.Open(filePath)
			if err != nil {
				close(done)
				errorMu.Lock()
				errors = append(errors, fmt.Errorf("failed to read file: %s", filePath))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			// create wrapped reader to track read progress
			progressReader := &progressReader{
				reader:   inputReader,
				progress: info.progress,
			}

			// create output file
			outputWriter, err := os.Create(info.outputPath)
			if err != nil {
				close(done)
				inputReader.Close()
				errorMu.Lock()
				errors = append(errors, fmt.Errorf("failed to create output file: %s", info.outputPath))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			// use streaming encryption
			_, err = neptuneCrypto.EncryptStream(progressReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize)
			
			// close file
			outputWriter.Close()
			inputReader.Close()
			close(done)
			
			if err != nil {
				errorMu.Lock()
				errors = append(errors, fmt.Errorf("encryption failed: %s (%v)", filePath, err))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			if encryptRemoveSource || encryptSecureRemoveSource {
				if err := os.Remove(filePath); err != nil {
					utils.PrintWarning("Failed to remove source file: %s", filePath)
				} else {
					utils.PrintSuccess("Source file removed: %s", filePath)
				}
			}

			mu.Lock()
			successCount++
			mu.Unlock()
		}(filePath, i)
	}

	// wait for all goroutines to complete
	wg.Wait()
	
	// clear progress display line
	fmt.Print("\r")

	// display final result
	utils.PrintInfo("encryption completed: %d success, %d failed, %d skipped (already encrypted)", successCount, failedCount, skippedCount)

	if len(errors) > 0 && failedCount > 0 {
		utils.PrintError("Some files failed to encrypt:")
		for i, e := range errors {
			if i < 5 {
				fmt.Printf("  - %v\n", e)
			}
		}
		if len(errors) > 5 {
			fmt.Printf("  ... and %d more errors\n", len(errors)-5)
		}
		return fmt.Errorf("partial file encryption failure")
	}

	if encryptSecureRemoveSource && len(files) > 0 {
		utils.SecureDeleteFiles(files)
	}

	return nil
}

func confirmRemoveFile(filePath string) bool {
	utils.PrintQuestion("Are you sure you want to remove source file %s? (y/N)", filePath)
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
	encryptCmd.Flags().BoolVar(&encryptSecureRemoveSource, "secure-remove-source", false, "Securely remove source file after successful encryption (delete + disable system recovery)")
	encryptCmd.Flags().BoolVarP(&encryptRecursive, "recursive", "R", false, "Recursively encrypt all files in a directory")
	encryptCmd.Flags().StringArrayVar(&encryptInclude, "include", []string{}, "Include files matching pattern (e.g., *.pdf)")
	encryptCmd.Flags().StringArrayVar(&encryptExclude, "exclude", []string{}, "Exclude files matching pattern (e.g., *.tmp)")
	encryptCmd.Flags().IntVar(&encryptTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")
	encryptCmd.Flags().StringVar(&encryptChunkSize, "chunk-size", "64KB", "Buffer size for stream encryption (e.g., 64KB, 1MB, 4MB)")
	encryptCmd.Flags().IntVar(&encryptParallel, "parallel", 1, "Number of parallel encryption processes for directories (default: 1)")

	encryptCmd.MarkFlagRequired("public-key")
	encryptCmd.MarkFlagRequired("private-key")
}