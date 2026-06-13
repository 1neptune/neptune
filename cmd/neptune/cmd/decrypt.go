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
	decryptInputFile     string
	decryptOutputFile    string
	decryptPrivateKey    string
	decryptKeyEncoding   string
	decryptForce         bool
	decryptRecursive     bool
	decryptInclude       []string
	decryptExclude       []string
	decryptTimeout       int
	decryptChunkSize     string // 流式解密的缓冲区大小
	decryptParallel      int    // 并行处理数
	decryptRemoveSource  bool   // 是否删除源文件
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

		// 解析并验证 chunk-size 参数
		chunkSize, err := utils.ParseChunkSize(decryptChunkSize)
		if err != nil {
			return err
		}
		if err := utils.ValidateChunkSize(chunkSize); err != nil {
			return err
		}

		// 验证 parallel 参数
		if decryptParallel < 1 {
			return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", decryptParallel), "必须大于等于 1")
		}
		if decryptParallel > 10 {
			utils.PrintWarning("并行数设置为 %d，建议不超过 10 以避免资源耗尽", decryptParallel)
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
			return decryptDirectory(decryptInputFile, decryptOutputFile, recipientKeyPair, chunkSize, decryptParallel)
		}

		// Handle single file decryption
		return decryptSingleFile(decryptInputFile, decryptOutputFile, recipientKeyPair, chunkSize)
	},
}

// decryptSingleFile 使用流式解密单个文件
// 参数:
//   - inputFile: 输入文件路径
//   - outputFile: 输出文件路径（如果为空，输出到 stdout）
//   - recipientKeyPair: 接收方的密钥对
//   - chunkSize: 流式处理的缓冲区大小
func decryptSingleFile(inputFile, outputFile string, recipientKeyPair *neptuneCurve25519.KeyPair, chunkSize int) error {
	// Validate input file
	if err := utils.ValidateFileForRead(inputFile); err != nil {
		return err
	}

	// 打开输入文件
	inputFileHandle, err := os.Open(inputFile)
	if err != nil {
		return utils.NewFileReadError(inputFile, err)
	}

	// 获取文件大小用于显示
	fileInfo, err := inputFileHandle.Stat()
	if err != nil {
		inputFileHandle.Close()
		return utils.NewFileReadError(inputFile, err)
	}
	inputFileSize := fileInfo.Size()

	// 准备输出目标
	var outputWriter io.Writer
	var outputFileHandle *os.File
	if outputFile != "" {
		// Validate output file
		if err := utils.ValidateFileForWrite(outputFile, decryptForce); err != nil {
			inputFileHandle.Close()
			return err
		}
		// 创建输出文件
		outputFileHandle, err = os.Create(outputFile)
		if err != nil {
			inputFileHandle.Close()
			return utils.NewFileWriteError(outputFile, err)
		}
		outputWriter = outputFileHandle
	} else {
		// 输出到 stdout
		outputWriter = os.Stdout
	}

	// 显示开始信息
	utils.PrintInfo("开始流式解密...")
	utils.PrintInfo("输入: %s (%s)", inputFile, utils.FormatFileSize(inputFileSize))
	utils.PrintInfo("缓冲区大小: %s", utils.FormatChunkSize(chunkSize))

	// 使用带进度显示的流式解密
	totalBytes, err := decryptStreamWithProgress(inputFileHandle, outputWriter, recipientKeyPair, chunkSize, inputFileSize)

	// 关闭输出文件
	if outputFileHandle != nil {
		outputFileHandle.Close()
	}

	// 关闭输入文件
	inputFileHandle.Close()

	if err != nil {
		return utils.NewDecryptError(err)
	}

	// 如果需要删除源文件
	if decryptRemoveSource {
		if err := os.Remove(inputFile); err != nil {
			utils.PrintWarning("删除加密文件失败: %s", inputFile)
		} else {
			utils.PrintSuccess("已删除加密文件: %s", inputFile)
		}
	}

	// 显示成功信息
	if outputFile != "" {
		utils.PrintSuccess("数据解密成功!")
		utils.PrintInfo("输入: %s (%s)", inputFile, utils.FormatFileSize(inputFileSize))
		utils.PrintInfo("输出: %s (%s)", outputFile, utils.FormatFileSize(totalBytes))
	}

	return nil
}

// decryptStreamWithProgress 使用带进度显示的流式解密
func decryptStreamWithProgress(reader io.Reader, writer io.Writer, recipientKeyPair *neptuneCurve25519.KeyPair, bufferSize int, totalSize int64) (int64, error) {
	// 读取头部信息
	header := make([]byte, neptuneCrypto.HeaderSize)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return 0, fmt.Errorf("读取头部失败: %w", err)
	}

	// 解析头部
	version := header[0]
	if version != neptuneCrypto.Version {
		return 0, neptuneCrypto.ErrInvalidVersion
	}

	var senderPubKey [neptuneCrypto.PublicKeySize]byte
	copy(senderPubKey[:], header[1:1+neptuneCrypto.PublicKeySize])
	var nonce [neptuneCrypto.NonceSize]byte
	copy(nonce[:], header[1+neptuneCrypto.PublicKeySize:])

	// 计算共享密钥
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(senderPubKey)
	if err != nil {
		return 0, fmt.Errorf("计算共享密钥失败: %w", err)
	}

	// 派生解密密钥
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)
	decryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("派生解密密钥失败: %w", err)
	}

	// 创建 Sosemanuk cipher
	cipher, err := sosemanuk.New(decryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("创建 cipher 失败: %w", err)
	}

	// 获取缓冲区
	buf := utils.GetGlobalBuffer(bufferSize)
	defer utils.PutGlobalBuffer(buf)
	
	// 确保缓冲区有足够的大小
	if cap(buf) < bufferSize {
		buf = make([]byte, bufferSize)
	} else {
		buf = buf[:bufferSize]
	}

	// 流式解密数据
	var processedBytes int64
	headerSize := int64(neptuneCrypto.HeaderSize)
	
	// 初始进度
	progress := float64(0)
	if totalSize > 0 && totalSize > headerSize {
		progress = float64(headerSize) / float64(totalSize) * 100
	}
	fmt.Printf("\r解密进度: %.1f%%", progress)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			// 解密数据
			cipher.XORKeyStream(buf[:n], buf[:n])
			
			// 写入输出
			nw, ew := writer.Write(buf[:n])
			if ew != nil {
				return processedBytes, fmt.Errorf("写入失败: %w", ew)
			}
			if nw != n {
				return processedBytes, fmt.Errorf("写入不完整")
			}
			
			processedBytes += int64(n)
			
			// 更新进度
			if totalSize > 0 && totalSize > headerSize {
				currentProgress := float64(headerSize+processedBytes) / float64(totalSize) * 100
				if currentProgress > 100 {
					currentProgress = 100
				}
				if int(currentProgress) != int(progress) {
					fmt.Printf("\r解密进度: %.1f%%", currentProgress)
					progress = currentProgress
				}
			}
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			return processedBytes, fmt.Errorf("读取失败: %w", err)
		}
	}

	// 显示最终进度
	fmt.Printf("\r解密进度: 100.0%%\n")
	
	return processedBytes, nil
}

// decryptDirectory 使用并行处理解密目录中的所有文件
// 参数:
//   - inputDir: 输入目录路径
//   - outputDir: 输出目录路径
//   - recipientKeyPair: 接收方的密钥对
//   - chunkSize: 流式处理的缓冲区大小
//   - parallel: 并行处理数
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
		return utils.NewInvalidInputError("input", "目录中没有找到匹配的加密文件")
	}

	// Create output directory if it doesn't exist
	if err := utils.EnsureDirectory(outputDir); err != nil {
		return err
	}

	utils.PrintInfo("找到 %d 个文件需要解密", len(files))
	utils.PrintInfo("并行数: %d, 缓冲区大小: %s", parallel, utils.FormatChunkSize(chunkSize))

	// 使用 semaphore 控制并发数
	semaphore := make(chan struct{}, parallel)

	// 使用 WaitGroup 等待所有任务完成
	var wg sync.WaitGroup

	// 使用原子计数器统计成功和失败数量
	var successCount int32
	var failedCount int32

	// 进度显示：已处理文件数
	var processedCount int32
	totalFiles := len(files)

	// 用于保护打印操作
	var printMu sync.Mutex

	// 进度更新时间控制（避免更新太频繁）
	var lastPrintTime int64
	const minPrintInterval int64 = 200 // 最小打印间隔（毫秒）

	// 遍历所有文件，并行处理
	for _, filePath := range files {
		wg.Add(1)

		go func(filePath string) {
			defer wg.Done()

			// 获取 semaphore，控制并发数
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Get relative path from input directory
			relPath, err := utils.GetRelativePathFromBase(inputDir, filePath)
			if err != nil {
				printMu.Lock()
				utils.PrintError("无法获取相对路径: %s", filePath)
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
				utils.PrintError("无法创建目录: %s", filepath.Dir(outputFilePath))
				printMu.Unlock()
				atomic.AddInt32(&failedCount, 1)
				atomic.AddInt32(&processedCount, 1)
				return
			}

			// 获取文件大小用于进度显示
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				printMu.Lock()
				utils.PrintError("无法获取文件信息: %s", filePath)
				printMu.Unlock()
				atomic.AddInt32(&failedCount, 1)
				atomic.AddInt32(&processedCount, 1)
				return
			}
			fileSize := fileInfo.Size()

			// 打开输入文件
			inputFileHandle, err := os.Open(filePath)
			if err != nil {
				printMu.Lock()
				utils.PrintError("无法读取文件: %s", filePath)
				printMu.Unlock()
				atomic.AddInt32(&failedCount, 1)
				atomic.AddInt32(&processedCount, 1)
				return
			}

			// 创建输出文件
			outputFileHandle, err := os.Create(outputFilePath)
			if err != nil {
				inputFileHandle.Close()
				printMu.Lock()
				utils.PrintError("无法创建文件: %s", outputFilePath)
				printMu.Unlock()
				atomic.AddInt32(&failedCount, 1)
				atomic.AddInt32(&processedCount, 1)
				return
			}

			// 使用带进度的解密
			_, err = decryptStreamWithProgressForFile(inputFileHandle, outputFileHandle, recipientKeyPair, chunkSize, filePath, fileSize, &processedCount, totalFiles, &printMu, &lastPrintTime, minPrintInterval)

			// 关闭文件
			inputFileHandle.Close()
			outputFileHandle.Close()

			if err != nil {
				// 删除已创建的输出文件
				os.Remove(outputFilePath)
				printMu.Lock()
				utils.PrintError("解密失败: %s", filePath)
				printMu.Unlock()
				atomic.AddInt32(&failedCount, 1)
				atomic.AddInt32(&processedCount, 1)
				return
			}

			// 如果需要删除源文件
			if decryptRemoveSource {
				if err := os.Remove(filePath); err != nil {
					printMu.Lock()
					utils.PrintWarning("删除加密文件失败: %s", filePath)
					printMu.Unlock()
				}
			}

			// 更新计数器
			currentProcessed := atomic.AddInt32(&processedCount, 1)
			atomic.AddInt32(&successCount, 1)

			// 显示最终进度（完成时）
			printMu.Lock()
			fileName := filepath.Base(filePath)
			fmt.Printf("\r[%s] [100.0%%] | 总进度: %d/%d (%.1f%%)\n", fileName, currentProcessed, totalFiles, float64(currentProcessed)/float64(totalFiles)*100)
			printMu.Unlock()
		}(filePath)
	}

	// 等待所有任务完成
	wg.Wait()

	// 清除可能的残留进度行
	fmt.Print("\r")

	// 显示最终结果
	utils.PrintInfo("解密完成: %d 成功, %d 失败", successCount, failedCount)

	if failedCount > 0 {
		return fmt.Errorf("部分文件解密失败")
	}

	return nil
}

// decryptStreamWithProgressForFile 使用带进度显示的流式解密单个文件
// 返回解密的总字节数和错误信息
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
	// 读取头部信息
	header := make([]byte, neptuneCrypto.HeaderSize)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return 0, fmt.Errorf("读取头部失败: %w", err)
	}

	// 解析头部
	version := header[0]
	if version != neptuneCrypto.Version {
		return 0, neptuneCrypto.ErrInvalidVersion
	}

	var senderPubKey [neptuneCrypto.PublicKeySize]byte
	copy(senderPubKey[:], header[1:1+neptuneCrypto.PublicKeySize])
	var nonce [neptuneCrypto.NonceSize]byte
	copy(nonce[:], header[1+neptuneCrypto.PublicKeySize:])

	// 计算共享密钥
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(senderPubKey)
	if err != nil {
		return 0, fmt.Errorf("计算共享密钥失败: %w", err)
	}

	// 派生解密密钥
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)
	decryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("派生解密密钥失败: %w", err)
	}

	// 创建 Sosemanuk cipher
	cipher, err := sosemanuk.New(decryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("创建 cipher 失败: %w", err)
	}

	// 获取缓冲区
	buf := utils.GetGlobalBuffer(bufferSize)
	defer utils.PutGlobalBuffer(buf)
	
	// 确保缓冲区有足够的大小
	if cap(buf) < bufferSize {
		buf = make([]byte, bufferSize)
	} else {
		buf = buf[:bufferSize]
	}

	// 流式解密数据
	var processedBytes int64
	headerSize := int64(neptuneCrypto.HeaderSize)

	// 初始进度
	progress := float64(0)
	if totalSize > 0 && totalSize > headerSize {
		progress = float64(headerSize) / float64(totalSize) * 100
	}

	// 获取文件名（不包含路径）
	displayName := fileName
	if idx := strings.LastIndex(fileName, string(filepath.Separator)); idx >= 0 {
		displayName = fileName[idx+1:]
	}

	currentProcessed := atomic.LoadInt32(processedCount)
	printMu.Lock()
	fmt.Printf("\r[%s] [%.1f%%] | 总进度: %d/%d (%.1f%%)", displayName, progress, currentProcessed, totalFiles, float64(currentProcessed)/float64(totalFiles)*100)
	printMu.Unlock()

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			// 解密数据
			cipher.XORKeyStream(buf[:n], buf[:n])

			// 写入输出
			nw, ew := writer.Write(buf[:n])
			if ew != nil {
				return processedBytes, fmt.Errorf("写入失败: %w", ew)
			}
			if nw != n {
				return processedBytes, fmt.Errorf("写入不完整")
			}

			processedBytes += int64(n)

			// 更新进度
			if totalSize > 0 && totalSize > headerSize {
				currentProgress := float64(headerSize+processedBytes) / float64(totalSize) * 100
				if currentProgress > 100 {
					currentProgress = 100
				}
				
				if int(currentProgress) != int(progress) {
					currentProcessed = atomic.LoadInt32(processedCount)
					printMu.Lock()
					fmt.Printf("\r[%s] [%.1f%%] | 总进度: %d/%d (%.1f%%)", displayName, currentProgress, currentProcessed, totalFiles, float64(currentProcessed)/float64(totalFiles)*100)
					printMu.Unlock()
					progress = currentProgress
				}
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return processedBytes, fmt.Errorf("读取失败: %w", err)
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
	decryptCmd.Flags().BoolVarP(&decryptRemoveSource, "remove-source", "r", false, "Remove encrypted source file after successful decryption")

	decryptCmd.MarkFlagRequired("input")
	decryptCmd.MarkFlagRequired("private-key")
}