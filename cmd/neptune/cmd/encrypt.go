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
	encryptRemoveSource    bool
	encryptRecursive       bool
	encryptInclude         []string
	encryptExclude         []string
	encryptTimeout         int
	encryptChunkSize       string // 流式加密的缓冲区大小
	encryptParallel        int    // 并行处理数
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
	// 解析缓冲区大小
	chunkSize, err := utils.ParseChunkSize(encryptChunkSize)
	if err != nil {
		return err
	}

	// 验证缓冲区大小
	if err := utils.ValidateChunkSize(chunkSize); err != nil {
		return err
	}

	// 对于文本加密，使用原有方式（数据量小，无需流式处理）
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

			utils.PrintSuccess("数据加密成功!")
			utils.PrintInfo("输入: 文本 (%s)", utils.FormatFileSize(int64(len(plaintext))))
			utils.PrintInfo("输出: %s (%s)", outputFile, utils.FormatFileSize(int64(len(ciphertext))))
			utils.PrintWarning("请妥善保管加密文件和密钥")
		} else {
			// Output to stdout
			if _, err := io.WriteString(os.Stdout, string(ciphertext)); err != nil {
				return utils.NewFileWriteError("stdout", err)
			}
		}

		return nil
	}

	// 对于文件加密，使用流式加密
	// Validate input file
	if err := utils.ValidateFileForRead(inputFile); err != nil {
		return err
	}

	// Check if file is already encrypted
	if err := utils.ValidateNotEncrypted(inputFile, encryptForceOverride); err != nil {
		return err
	}

	// 获取文件大小用于显示
	fileSize, err := utils.GetFileSize(inputFile)
	if err != nil {
		return err
	}

	// 打开输入文件
	inputReader, err := os.Open(inputFile)
	if err != nil {
		return utils.NewFileReadError(inputFile, err)
	}

	// 创建输出文件
	if outputFile == "" {
		// 如果没有指定输出文件，输出到 stdout
		outputWriter := os.Stdout
		
		utils.PrintInfo("开始流式加密...")
		utils.PrintInfo("输入: %s (%s)", inputFile, utils.FormatFileSize(fileSize))
		utils.PrintInfo("缓冲区大小: %s", utils.FormatChunkSize(chunkSize))
		
		// 使用带进度显示的流式加密
		totalBytes, err := encryptStreamWithProgress(inputReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize, fileSize)
		if err != nil {
			return err
		}
		
		utils.PrintSuccess("数据加密成功!")
		utils.PrintInfo("加密数据量: %s", utils.FormatFileSize(totalBytes))
		utils.PrintWarning("请妥善保管加密文件和密钥")
		
		inputReader.Close()
		return nil
	}

	// Validate output file
	if err := utils.ValidateFileForWrite(outputFile, encryptForce); err != nil {
		return err
	}

	// 创建输出文件
	outputWriter, err := os.Create(outputFile)
	if err != nil {
		return utils.NewFileWriteError(outputFile, err)
	}
	defer outputWriter.Close()

	utils.PrintInfo("开始流式加密...")
	utils.PrintInfo("输入: %s (%s)", inputFile, utils.FormatFileSize(fileSize))
	utils.PrintInfo("缓冲区大小: %s", utils.FormatChunkSize(chunkSize))

	// 使用带进度显示的流式加密
	totalBytes, err := encryptStreamWithProgress(inputReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize, fileSize)
	if err != nil {
		return err
	}

	// 获取输出文件大小
	outputFileSize, err := utils.GetFileSize(outputFile)
	if err != nil {
		outputFileSize = totalBytes + neptuneCrypto.HeaderSize // 估算大小
	}

	utils.PrintSuccess("数据加密成功!")
	utils.PrintInfo("输入: %s (%s)", inputFile, utils.FormatFileSize(fileSize))
	utils.PrintInfo("输出: %s (%s)", outputFile, utils.FormatFileSize(outputFileSize))
	utils.PrintWarning("请妥善保管加密文件和密钥")

	// Close input file before removing
	inputReader.Close()

	// Remove source file if requested
	if encryptRemoveSource && inputFile != "" {
		if err := os.Remove(inputFile); err != nil {
			return utils.NewFileDeleteError(inputFile, err)
		}
		utils.PrintSuccess("源文件已删除: %s", inputFile)
	}

	return nil
}

// encryptStreamWithProgress 使用带进度显示的流式加密
func encryptStreamWithProgress(plaintext io.Reader, writer io.Writer, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte, bufferSize int, totalSize int64) (int64, error) {
	// 计算共享密钥
	sharedSecret, err := senderKeyPair.ComputeSharedSecret(recipientPublicKey)
	if err != nil {
		return 0, fmt.Errorf("计算共享密钥失败: %w", err)
	}

	// 派生加密密钥
	context := append([]byte("neptune-encryption"), recipientPublicKey[:]...)
	encryptionKey, err := neptuneCrypto.DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("派生加密密钥失败: %w", err)
	}

	// 生成随机 nonce
	nonce, err := neptuneCrypto.GenerateNonce()
	if err != nil {
		return 0, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	// 创建 Sosemanuk cipher
	cipher, err := neptuneSosemanuk.New(encryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("创建 cipher 失败: %w", err)
	}

	// 写入头部信息
	// 格式: [Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes]
	header := make([]byte, neptuneCrypto.HeaderSize)
	header[0] = neptuneCrypto.Version
	copy(header[1:], senderKeyPair.PublicKey[:])
	copy(header[1+neptuneCurve25519.KeySize:], nonce[:])

	if _, err := writer.Write(header); err != nil {
		return 0, fmt.Errorf("写入头部失败: %w", err)
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

	// 流式加密数据
	var processedBytes int64
	headerSize := int64(neptuneCrypto.HeaderSize)

	// 初始进度
	progress := float64(0)
	if totalSize > 0 && totalSize > headerSize {
		progress = float64(headerSize) / float64(totalSize) * 100
	}
	fmt.Printf("\r加密进度: %.1f%%", progress)

	for {
		n, err := plaintext.Read(buf)
		if n > 0 {
			// 加密数据块
			encryptedChunk := make([]byte, n)
			cipher.XORKeyStream(encryptedChunk, buf[:n])

			// 写入加密数据
			nw, ew := writer.Write(encryptedChunk)
			if ew != nil {
				return processedBytes, fmt.Errorf("写入加密数据失败: %w", ew)
			}
			if nw != n {
				return processedBytes, fmt.Errorf("写入不完整")
			}

			processedBytes += int64(n)

			// 更新进度（每 1% 更新一次）
			if totalSize > 0 {
				currentProgress := float64(processedBytes) / float64(totalSize) * 100
				if currentProgress > 100 {
					currentProgress = 100
				}
				if int(currentProgress) != int(progress) {
					fmt.Printf("\r加密进度: %.1f%%", currentProgress)
					progress = currentProgress
				}
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return processedBytes, fmt.Errorf("读取明文数据失败: %w", err)
		}
	}

	// 显示最终进度
	fmt.Printf("\r加密进度: 100.0%%\n")

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

	utils.PrintSuccess("数据加密成功!")
	utils.PrintInfo("输入: 远程数据 (%s)", utils.FormatFileSize(int64(len(data))))
	utils.PrintInfo("输出: %s (%s)", outputFile, utils.FormatFileSize(int64(len(ciphertext))))
	utils.PrintWarning("请妥善保管加密文件和密钥")

	return nil
}

// fileProgress 用于跟踪单个文件的加密进度
type fileProgress struct {
	fileName       string
	processedBytes int64
	totalBytes     int64
	mu             sync.Mutex
}

// updateProgress 更新文件进度
func (p *fileProgress) updateProgress(processed int64) {
	p.mu.Lock()
	p.processedBytes = processed
	p.mu.Unlock()
}

// getProgress 获取当前进度
func (p *fileProgress) getProgress() (string, int64, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	progress := p.processedBytes
	total := p.totalBytes
	fileName := p.fileName
	return fileName, progress, total
}

// progressReader 包装 io.Reader，跟踪已读取的字节数
type progressReader struct {
	reader   io.Reader
	progress *fileProgress
	readBytes int64
}

// Read 实现 io.Reader 接口，同时跟踪读取进度
func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	pr.readBytes += int64(n)
	pr.progress.updateProgress(pr.readBytes)
	return
}

func encryptDirectory(inputDir, outputDir string, senderKeyPair *neptuneCurve25519.KeyPair, recipientPublicKey [neptuneCurve25519.KeySize]byte) error {
	// 解析缓冲区大小
	chunkSize, err := utils.ParseChunkSize(encryptChunkSize)
	if err != nil {
		return err
	}

	// 验证缓冲区大小
	if err := utils.ValidateChunkSize(chunkSize); err != nil {
		return err
	}

	// 验证并行数
	if encryptParallel < 1 {
		return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", encryptParallel), "必须大于 0")
	}
	if encryptParallel > 10 {
		return utils.NewInvalidParameterError("parallel", fmt.Sprintf("%d", encryptParallel), "不能超过 10")
	}

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
	utils.PrintInfo("并行处理数: %d", encryptParallel)
	utils.PrintInfo("缓冲区大小: %s", utils.FormatChunkSize(chunkSize))

	// 用于跟踪每个文件的进度
	type fileInfo struct {
		relPath    string
		outputPath string
		fileSize   int64
		progress   *fileProgress
	}
	
	// 预计算所有文件的信息和总大小
	fileInfos := make([]fileInfo, 0, len(files))
	var totalSize int64
	for _, filePath := range files {
		relPath, _ := utils.GetRelativePathFromBase(inputDir, filePath)
		fileSize, _ := utils.GetFileSize(filePath)
		outputPath := filepath.Join(outputDir, relPath+".ntp")
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

	// 创建 semaphore 控制并发数
	sem := make(chan struct{}, encryptParallel)

	// 用于统计结果
	var successCount, failedCount, skippedCount int32
	var mu sync.Mutex // 保护计数器

	// 进度显示
	var completedFiles int32
	totalFiles := len(files)

	// 创建 WaitGroup 等待所有 goroutine 完成
	var wg sync.WaitGroup

	// 创建错误收集器
	var errors []error
	errorMu := sync.Mutex{}
	
	// 处理每个文件
	for i, filePath := range files {
		wg.Add(1)

		go func(filePath string, idx int) {
			defer wg.Done()

			// 获取 semaphore（控制并发数）
			sem <- struct{}{}
			defer func() { <-sem }() // 释放 semaphore

			info := &fileInfos[idx]

			// 更新整体进度
			mu.Lock()
			completedFiles++
			mu.Unlock()

			// 启动进度显示 goroutine
			done := make(chan struct{})
			go func() {
				ticker := time.NewTicker(100 * time.Millisecond) // 更频繁更新
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
							fmt.Printf("\r[%s] [%.1f%%] | 进度: %d/%d (%.1f%%)", fileName, filePercent, currentCount, totalFiles, overallPercent)
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
				errors = append(errors, fmt.Errorf("无法检查文件状态: %s", filePath))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			if isEncrypted {
				if encryptForceOverride {
					// 继续加密
				} else {
					close(done)
					mu.Lock()
					skippedCount++
					mu.Unlock()
					return
				}
			}

			// 打开输入文件
			inputReader, err := os.Open(filePath)
			if err != nil {
				close(done)
				errorMu.Lock()
				errors = append(errors, fmt.Errorf("无法读取文件: %s", filePath))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			// 创建包装 reader 来跟踪读取进度
			progressReader := &progressReader{
				reader:   inputReader,
				progress: info.progress,
			}

			// 创建输出文件
			outputWriter, err := os.Create(info.outputPath)
			if err != nil {
				close(done)
				inputReader.Close()
				errorMu.Lock()
				errors = append(errors, fmt.Errorf("无法创建输出文件: %s", info.outputPath))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			// 使用流式加密
			_, err = neptuneCrypto.EncryptStream(progressReader, outputWriter, senderKeyPair, recipientPublicKey, chunkSize)
			
			// 关闭文件
			outputWriter.Close()
			inputReader.Close()
			close(done)
			
			if err != nil {
				errorMu.Lock()
				errors = append(errors, fmt.Errorf("加密失败: %s (%v)", filePath, err))
				errorMu.Unlock()
				mu.Lock()
				failedCount++
				mu.Unlock()
				return
			}

			// Remove source file if requested
			if encryptRemoveSource {
				if encryptForce {
					if err := os.Remove(filePath); err != nil {
						utils.PrintWarning("删除源文件失败: %s", filePath)
					} else {
						utils.PrintSuccess("已删除源文件: %s", filePath)
					}
				}
			}

			mu.Lock()
			successCount++
			mu.Unlock()
		}(filePath, i)
	}

	// 等待所有 goroutine 完成
	wg.Wait()
	
	// 清除进度显示行
	fmt.Print("\r")

	// 显示最终结果
	utils.PrintInfo("加密完成: %d 成功, %d 失败, %d 跳过(已加密)", successCount, failedCount, skippedCount)

	// 显示错误详情（如果有）
	if len(errors) > 0 && failedCount > 0 {
		utils.PrintError("部分文件加密失败:")
		for i, e := range errors {
			if i < 5 { // 只显示前 5 个错误
				fmt.Printf("  - %v\n", e)
			}
		}
		if len(errors) > 5 {
			fmt.Printf("  ... 还有 %d 个错误\n", len(errors)-5)
		}
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
	encryptCmd.Flags().StringVar(&encryptChunkSize, "chunk-size", "64KB", "Buffer size for stream encryption (e.g., 64KB, 1MB, 4MB)")
	encryptCmd.Flags().IntVar(&encryptParallel, "parallel", 1, "Number of parallel encryption processes for directories (default: 1)")

	encryptCmd.MarkFlagRequired("public-key")
	encryptCmd.MarkFlagRequired("private-key")
}