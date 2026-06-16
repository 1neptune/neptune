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

	decryptInputFile          string

	decryptOutputFile         string

	decryptPrivateKey         string

	decryptKeyEncoding        string

	decryptForce              bool

	decryptRecursive          bool

	decryptInclude            []string

	decryptExclude            []string

	decryptTimeout            int

	decryptChunkSize          string // buffer size for streaming decryption

	decryptParallel           int    // number of parallel processes

	decryptRemoveSource       bool   // whether to remove source file (normal delete)

	decryptSecureRemoveSource bool   // whether to securely remove source file

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

  neptune decrypt --input encrypted/ --output decrypted/ --private-key my.key --recursive --include "*.ntp"



  # Decrypt and remove source file (normal delete)

  neptune decrypt --input secret.ntp --output secret.txt --private-key my.key --remove-source



  # Decrypt and secure remove source file (delete + disable recovery features)

  neptune decrypt --input secret.ntp --output secret.txt --private-key my.key --secure-remove-source`,

	RunE: func(cmd *cobra.Command, args []string) error {

		// Validate inputs

		if decryptInputFile == "" {

			return utils.NewMissingInputError("input")

		}

		if decryptPrivateKey == "" {

			return utils.NewMissingInputError("private-key")

		}



		// --input parameter must be a local file path, cannot be URL

		if utils.IsHTTPURL(decryptInputFile) {

			return &utils.NeptuneError{

				Code:   utils.ErrCodeInvalidInput,

				Message: "--input parameter does not support URL",

				Suggestion: "please use a local file path",

			}

		}



		// parse and validate chunk-size parameter

		chunkSize, err := utils.ParseChunkSize(decryptChunkSize)

		if err != nil {

			return err

		}

		if err := utils.ValidateChunkSize(chunkSize); err != nil {

			return err

		}



		// validate parallel parameter

		if decryptParallel < 1 {

			return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", decryptParallel), "must be greater than or equal to 1")

		}

		if decryptParallel > 10 {

			utils.PrintWarning(" %d，greater than 10 to avoid resource exhaustion", decryptParallel)

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



		// Load recipient's private key (memory-only)

		var recipientKeyPair *neptuneCurve25519.KeyPair

		var keyData []byte

		if utils.IsHTTPURL(decryptPrivateKey) {

			utils.PrintInfo("Loading private key from remote to memory: %s", decryptPrivateKey)

			keyData, err = utils.DownloadBytes(decryptPrivateKey, timeout)

			if err != nil {

				return err

			}

			recipientKeyPair, err = neptuneCurve25519.LoadKeyPairFromBytes(keyData, neptuneCurve25519.EncodingType(keyEncoding))

			if err != nil {

				return utils.NewKeyReadError(decryptPrivateKey, err)

			}

			// clear key data

			utils.PrintInfo("[Memory] Clearing downloaded private key data (%d bytes)...", len(keyData))

			utils.SecureZeroMemory(keyData)

			utils.PrintSuccess("[Memory] Private key data cleared from memory")

		} else {

			if err := utils.ValidateFilePath(decryptPrivateKey); err != nil {

				return err

			}

			recipientKeyPair, err = neptuneCurve25519.LoadKeyPairFromFile(decryptPrivateKey, neptuneCurve25519.EncodingType(keyEncoding))

			if err != nil {

				return utils.NewKeyReadError(decryptPrivateKey, err)

			}

		}



		// clear key URL parameter

		utils.PrintInfo("[Memory] Clearing private key URL...")

		utils.SecureWipeString(&decryptPrivateKey)

		utils.PrintSuccess("[Memory] Private key URL cleared from memory")



		// Check if input is a directory

		info, err := os.Stat(decryptInputFile)

		if err != nil {

			return utils.NewFileReadError(decryptInputFile, err)

		}



		if info.IsDir() {

			if !decryptRecursive {

				return utils.NewInvalidInputError("input", "input is a directory, please use --recursive option")

			}

			return decryptDirectory(decryptInputFile, decryptOutputFile, recipientKeyPair, chunkSize, decryptParallel)

		}



		// Handle single file decryption

		return decryptSingleFile(decryptInputFile, decryptOutputFile, recipientKeyPair, chunkSize)

	},

}



// decryptSingleFile 

// [comment]
//   - inputFile: 

//   - outputFile: （， stdout）

//   - recipientKeyPair: 

//   - chunkSize: 

func decryptSingleFile(inputFile, outputFile string, recipientKeyPair *neptuneCurve25519.KeyPair, chunkSize int) error {

	// Validate input file

	if err := utils.ValidateFileForRead(inputFile); err != nil {

		return err

	}



	// [comment]
	inputFileHandle, err := os.Open(inputFile)

	if err != nil {

		return utils.NewFileReadError(inputFile, err)

	}



	// [comment]
	fileInfo, err := inputFileHandle.Stat()

	if err != nil {

		inputFileHandle.Close()

		return utils.NewFileReadError(inputFile, err)

	}

	inputFileSize := fileInfo.Size()



	// [comment]
	var outputWriter io.Writer

	var outputFileHandle *os.File

	if outputFile != "" {

		// Validate output file

		if err := utils.ValidateFileForWrite(outputFile, decryptForce); err != nil {

			inputFileHandle.Close()

			return err

		}

		// [comment]
		outputFileHandle, err = os.Create(outputFile)

		if err != nil {

			inputFileHandle.Close()

			return utils.NewFileWriteError(outputFile, err)

		}

		outputWriter = outputFileHandle

	} else {

		//  stdout

		outputWriter = os.Stdout

	}



	// [comment]
	utils.PrintInfo("Starting streaming decryption...")
	utils.PrintInfo("Input: %s (%s)", inputFile, utils.FormatFileSize(inputFileSize))
	utils.PrintInfo("Buffer size: %s", utils.FormatChunkSize(chunkSize))



	// [comment]
	totalBytes, err := decryptStreamWithProgress(inputFileHandle, outputWriter, recipientKeyPair, chunkSize, inputFileSize)



	// [comment]
	if outputFileHandle != nil {

		outputFileHandle.Close()

	}



	// [comment]
	inputFileHandle.Close()



	if err != nil {

		return utils.NewDecryptError(err)

	}



	if decryptSecureRemoveSource {
		utils.SecureDeleteFiles([]string{inputFile})
	}

	if decryptRemoveSource || decryptSecureRemoveSource {
		if err := os.Remove(inputFile); err != nil {
			utils.PrintWarning("Failed to remove source file: %s", inputFile)
		} else {
			utils.PrintSuccess("Source file removed: %s", inputFile)
		}
	}



	// [comment]
	if outputFile != "" {
		utils.PrintSuccess("Data decryption successful!")
		utils.PrintInfo("Input: %s (%s)", inputFile, utils.FormatFileSize(inputFileSize))
		utils.PrintInfo("Output: %s (%s)", outputFile, utils.FormatFileSize(totalBytes))
	}



	return nil

}



// decryptStreamWithProgress 

func decryptStreamWithProgress(reader io.Reader, writer io.Writer, recipientKeyPair *neptuneCurve25519.KeyPair, bufferSize int, totalSize int64) (int64, error) {

	// [comment]
	header := make([]byte, neptuneCrypto.HeaderSize)

	_, err := io.ReadFull(reader, header)

	if err != nil {

		return 0, fmt.Errorf("read failed: %w", err)

	}



	// [comment]
	version := header[0]

	if version != neptuneCrypto.Version {

		return 0, neptuneCrypto.ErrInvalidVersion

	}



	var senderPubKey [neptuneCrypto.PublicKeySize]byte

	copy(senderPubKey[:], header[1:1+neptuneCrypto.PublicKeySize])

	var nonce [neptuneCrypto.NonceSize]byte

	copy(nonce[:], header[1+neptuneCrypto.PublicKeySize:])



	// [comment]
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(senderPubKey)

	if err != nil {

		return 0, fmt.Errorf("read failed: %w", err)

	}



	// [comment]
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)

	decryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)

	if err != nil {

		return 0, fmt.Errorf("read failed: %w", err)

	}



	//  Sosemanuk cipher

	cipher, err := sosemanuk.New(decryptionKey, nonce[:])

	if err != nil {

		return 0, fmt.Errorf("create cipher failed: %w", err)

	}



	// [comment]
	buf := utils.GetGlobalBuffer(bufferSize)

	defer utils.PutGlobalBuffer(buf)

	

	// [comment]
	if cap(buf) < bufferSize {

		buf = make([]byte, bufferSize)

	} else {

		buf = buf[:bufferSize]

	}



	// [comment]
	var processedBytes int64

	headerSize := int64(neptuneCrypto.HeaderSize)

	

	// [comment]
	progress := float64(0)

	if totalSize > 0 && totalSize > headerSize {

		progress = float64(headerSize) / float64(totalSize) * 100

	}

	fmt.Printf("\rDecryption progress: %.1f%%", progress)



	for {

		n, err := reader.Read(buf)

		if n > 0 {

			// [comment]
			cipher.XORKeyStream(buf[:n], buf[:n])

			

			// [comment]
			nw, ew := writer.Write(buf[:n])

			if ew != nil {

				return processedBytes, fmt.Errorf("write failed: %w", ew)

			}

			if nw != n {

				return processedBytes, fmt.Errorf("incomplete write")

			}

			

			processedBytes += int64(n)

			

			// [comment]
			if totalSize > 0 && totalSize > headerSize {

				currentProgress := float64(headerSize+processedBytes) / float64(totalSize) * 100

				if currentProgress > 100 {

					currentProgress = 100

				}

				if int(currentProgress) != int(progress) {
					fmt.Printf("\rDecryption progress: %.1f%%", currentProgress)
					progress = currentProgress
				}

			}

		}

		

		if err == io.EOF {

			break

		}

		if err != nil {

			return processedBytes, fmt.Errorf("read failed: %w", err)

		}

	}



	// [comment]
	fmt.Printf("\rDecryption progress: 100.0%%\n")

	// ========== Memory cleanup: clear sensitive data ==========
	utils.PrintInfo("[Memory] Clearing decryption key...")
	utils.SecureZeroMemory(sharedSecret[:])
	utils.SecureZeroMemory(decryptionKey)
	utils.PrintSuccess("[Memory] Decryption key cleared from memory")

	utils.PrintInfo("[Memory] Clearing nonce...")
	utils.SecureZeroMemory(nonce[:])
	utils.PrintSuccess("[Memory] Nonce cleared from memory")

	utils.PrintInfo("[Memory] Clearing context data...")
	utils.SecureZeroMemory(context)
	utils.PrintSuccess("[Memory] Context data cleared from memory")

	utils.PrintInfo("[Memory] Clearing sender public key...")
	utils.SecureZeroMemory(senderPubKey[:])
	utils.PrintSuccess("[Memory] Sender public key cleared")

	utils.PrintInfo("[Memory] Clearing header buffer...")
	utils.SecureZeroMemory(header)
	utils.PrintSuccess("[Memory] Header buffer cleared")

	return processedBytes, nil
}



// decryptDirectory 

// [comment]
//   - inputDir: 

//   - outputDir: 

//   - recipientKeyPair: 

//   - chunkSize: 

//   - parallel: number of parallel processes

func decryptDirectory(inputDir, outputDir string, recipientKeyPair *neptuneCurve25519.KeyPair, chunkSize int, parallel int) error {

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

		return utils.NewInvalidInputError("input", "")

	}



	// Create output directory if it doesn't exist

	if err := utils.EnsureDirectory(outputDir); err != nil {

		return err

	}



	utils.PrintInfo("Found %d files to decrypt", len(files))

	utils.PrintInfo("Parallel processes: %d, Buffer size: %s", parallel, utils.FormatChunkSize(chunkSize))



	//  semaphore 

	semaphore := make(chan struct{}, parallel)



	//  WaitGroup 

	var wg sync.WaitGroup



	// [comment]
	var successCount int32

	var failedCount int32



	// [comment]
	var processedCount int32

	totalFiles := len(files)



	// [comment]
	var printMu sync.Mutex



	// [comment]
	var lastPrintTime int64

	const minPrintInterval int64 = 200 // [comment]
	// [comment]
	for _, filePath := range files {

		wg.Add(1)



		go func(filePath string) {

			defer wg.Done()



			//  semaphore，

			semaphore <- struct{}{}

			defer func() { <-semaphore }()



			// Get relative path from input directory

			relPath, err := utils.GetRelativePathFromBase(inputDir, filePath)

			if err != nil {

				printMu.Lock()

				utils.PrintError("Failed: %s", filePath)

				printMu.Unlock()

				atomic.AddInt32(&failedCount, 1)

				atomic.AddInt32(&processedCount, 1)

				return

			}



			// Remove .ntp extension from output path

			outputFilePath := filepath.Join(outputDir, strings.TrimSuffix(relPath, ".ntp"))



			// Ensure parent directory exists

			if err := utils.EnsureParentDirectory(outputFilePath); err != nil {

				printMu.Lock()

				utils.PrintError("Failed to create directory: %s", filepath.Dir(outputFilePath))

				printMu.Unlock()

				atomic.AddInt32(&failedCount, 1)

				atomic.AddInt32(&processedCount, 1)

				return

			}



			// [comment]
			fileInfo, err := os.Stat(filePath)

			if err != nil {

				printMu.Lock()

				utils.PrintError("Failed: %s", filePath)

				printMu.Unlock()

				atomic.AddInt32(&failedCount, 1)

				atomic.AddInt32(&processedCount, 1)

				return

			}

			fileSize := fileInfo.Size()



			// [comment]
			inputFileHandle, err := os.Open(filePath)

			if err != nil {

				printMu.Lock()

				utils.PrintError("Failed: %s", filePath)

				printMu.Unlock()

				atomic.AddInt32(&failedCount, 1)

				atomic.AddInt32(&processedCount, 1)

				return

			}



			// [comment]
			outputFileHandle, err := os.Create(outputFilePath)

			if err != nil {

				inputFileHandle.Close()

				printMu.Lock()

				utils.PrintError("Failed to create output file: %s", outputFilePath)

				printMu.Unlock()

				atomic.AddInt32(&failedCount, 1)

				atomic.AddInt32(&processedCount, 1)

				return

			}



			// [comment]
			_, err = decryptStreamWithProgressForFile(inputFileHandle, outputFileHandle, recipientKeyPair, chunkSize, filePath, fileSize, &processedCount, totalFiles, &printMu, &lastPrintTime, minPrintInterval)



			// [comment]
			inputFileHandle.Close()

			outputFileHandle.Close()



			if err != nil {

				// [comment]
				os.Remove(outputFilePath)

				printMu.Lock()

				utils.PrintError("Failed: %s", filePath)

				printMu.Unlock()

				atomic.AddInt32(&failedCount, 1)

				atomic.AddInt32(&processedCount, 1)

				return

			}



			// [comment]
			if decryptRemoveSource || decryptSecureRemoveSource {

				if err := os.Remove(filePath); err != nil {

					printMu.Lock()

					utils.PrintWarning("Failed to remove source file: %s", filePath)

					printMu.Unlock()

				}

			}



			// [comment]
			currentProcessed := atomic.AddInt32(&processedCount, 1)

			atomic.AddInt32(&successCount, 1)



			// [comment]
			printMu.Lock()

			fileName := filepath.Base(filePath)

			fmt.Printf("\r[%s] [100.0%%] | Progress: %d/%d (%.1f%%)\n", fileName, currentProcessed, totalFiles, float64(currentProcessed)/float64(totalFiles)*100)

			printMu.Unlock()

		}(filePath)

	}



	// [comment]
	wg.Wait()



	// [comment]
	if decryptSecureRemoveSource && successCount > 0 {

		utils.PrintInfo("Starting secure deletion...")

		var deletedFiles []string

		for _, filePath := range files {

			if _, err := os.Stat(filePath); os.IsNotExist(err) {

				deletedFiles = append(deletedFiles, filePath)

			}

		}

		if len(deletedFiles) > 0 {

			utils.SecureDeleteFiles(deletedFiles)

		}

	}



	// [comment]
	fmt.Print("\r")



	// [comment]
	utils.PrintInfo("Decryption completed: %d success, %d failed", successCount, failedCount)



	if failedCount > 0 {

		return fmt.Errorf("partial file decryption failure")

	}



	return nil

}



// decryptStreamWithProgressForFile 

// [comment]
func decryptStreamWithProgressForFile(

	reader io.Reader,

	writer io.Writer,

	recipientKeyPair *neptuneCurve25519.KeyPair,

	bufferSize int,

	fileName string,

	totalSize int64,

	processedCount *int32,

	totalFiles int,

	printMu *sync.Mutex,

	lastPrintTime *int64,

	minPrintInterval int64,

) (int64, error) {

	// [comment]
	header := make([]byte, neptuneCrypto.HeaderSize)

	_, err := io.ReadFull(reader, header)

	if err != nil {

		return 0, fmt.Errorf("read failed: %w", err)

	}



	// [comment]
	version := header[0]

	if version != neptuneCrypto.Version {

		return 0, neptuneCrypto.ErrInvalidVersion

	}



	var senderPubKey [neptuneCrypto.PublicKeySize]byte

	copy(senderPubKey[:], header[1:1+neptuneCrypto.PublicKeySize])

	var nonce [neptuneCrypto.NonceSize]byte

	copy(nonce[:], header[1+neptuneCrypto.PublicKeySize:])



	// [comment]
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(senderPubKey)

	if err != nil {

		return 0, fmt.Errorf("read failed: %w", err)

	}



	// [comment]
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)

	decryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)

	if err != nil {

		return 0, fmt.Errorf("read failed: %w", err)

	}



	//  Sosemanuk cipher

	cipher, err := sosemanuk.New(decryptionKey, nonce[:])

	if err != nil {

		return 0, fmt.Errorf("create cipher failed: %w", err)

	}



	// [comment]
	buf := utils.GetGlobalBuffer(bufferSize)

	defer utils.PutGlobalBuffer(buf)

	

	// [comment]
	if cap(buf) < bufferSize {

		buf = make([]byte, bufferSize)

	} else {

		buf = buf[:bufferSize]

	}



	// [comment]
	var processedBytes int64

	headerSize := int64(neptuneCrypto.HeaderSize)



	// [comment]
	progress := float64(0)

	if totalSize > 0 && totalSize > headerSize {

		progress = float64(headerSize) / float64(totalSize) * 100

	}



	// [comment]
	displayName := fileName

	if idx := strings.LastIndex(fileName, string(filepath.Separator)); idx >= 0 {

		displayName = fileName[idx+1:]

	}



	currentProcessed := atomic.LoadInt32(processedCount)

	printMu.Lock()

	fmt.Printf("\r[%s] [%.1f%%] | Progress: %d/%d (%.1f%%)", displayName, progress, currentProcessed, totalFiles, float64(currentProcessed)/float64(totalFiles)*100)

	printMu.Unlock()



	for {

		n, err := reader.Read(buf)

		if n > 0 {

			// [comment]
			cipher.XORKeyStream(buf[:n], buf[:n])



			// [comment]
			nw, ew := writer.Write(buf[:n])

			if ew != nil {

				return processedBytes, fmt.Errorf("write failed: %w", ew)

			}

			if nw != n {

				return processedBytes, fmt.Errorf("incomplete write")

			}



			processedBytes += int64(n)



			// [comment]
			if totalSize > 0 && totalSize > headerSize {

				currentProgress := float64(headerSize+processedBytes) / float64(totalSize) * 100

				if currentProgress > 100 {

					currentProgress = 100

				}

				

				if int(currentProgress) != int(progress) {

					currentProcessed = atomic.LoadInt32(processedCount)

					printMu.Lock()

					fmt.Printf("\r[%s] [%.1f%%] | Progress: %d/%d (%.1f%%)", displayName, currentProgress, currentProcessed, totalFiles, float64(currentProcessed)/float64(totalFiles)*100)

					printMu.Unlock()

					progress = currentProgress

				}

			}

		}



		if err == io.EOF {

			break

		}

		if err != nil {

			return processedBytes, fmt.Errorf("read failed: %w", err)

		}

	}



	return processedBytes, nil

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

	decryptCmd.Flags().StringVar(&decryptChunkSize, "chunk-size", "64KB", "Buffer size for streaming decryption (e.g., 64KB, 1MB, 4MB)")

	decryptCmd.Flags().IntVar(&decryptParallel, "parallel", 1, "Number of parallel decryption threads (default: 1)")

	decryptCmd.Flags().BoolVarP(&decryptRemoveSource, "remove-source", "r", false, "Remove encrypted source file after successful decryption (normal delete)")

	decryptCmd.Flags().BoolVar(&decryptSecureRemoveSource, "secure-remove-source", false, "Securely remove encrypted source file after successful decryption (delete + disable recovery features)")



	decryptCmd.MarkFlagRequired("input")

	decryptCmd.MarkFlagRequired("private-key")

}