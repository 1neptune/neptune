package utils

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// MaxFileSize is the maximum allowed file size for encryption (100MB)
	MaxFileSize int64 = 100 * 1024 * 1024

	// KeySize is the expected size for Curve25519 keys (32 bytes)
	KeySize = 32

	// MinKeyFileSize is the minimum file size for a key file
	MinKeyFileSize int64 = 32 // At least 32 bytes for hex encoded key

	// NeptuneFileExtension is the file extension for encrypted files
	NeptuneFileExtension = ".ntp"

	// NeptuneMinHeaderSize is the minimum size for a valid Neptune encrypted file
	NeptuneMinHeaderSize = 49 // 1 byte version + 32 bytes public key + 16 bytes nonce
)

// EncodingType defines the encoding format for keys
type EncodingType int

const (
	EncodingHex EncodingType = iota
	EncodingBase64
	EncodingBase64URL
)

// ParseEncodingType parses a string to EncodingType
func ParseEncodingType(s string) (EncodingType, error) {
	switch strings.ToLower(s) {
	case "hex":
		return EncodingHex, nil
	case "base64":
		return EncodingBase64, nil
	case "base64url":
		return EncodingBase64URL, nil
	default:
		return EncodingHex, NewInvalidEncodingError(s, []string{"hex", "base64", "base64url"})
	}
}

// String returns the string representation of EncodingType
func (e EncodingType) String() string {
	switch e {
	case EncodingHex:
		return "hex"
	case EncodingBase64:
		return "base64"
	case EncodingBase64URL:
		return "base64url"
	default:
		return "unknown"
	}
}

// FileExists checks if a file exists and is accessible
func FileExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewFileNotFoundError(path, err)
		}
		if os.IsPermission(err) {
			return NewFilePermissionError(path, err)
		}
		return NewFileReadError(path, err)
	}

	if info.IsDir() {
		return NewInvalidPathError(path, fmt.Errorf("路径是目录而非文件"))
	}

	return nil
}

// ValidateFileForRead validates a file for reading
func ValidateFileForRead(path string) error {
	// Check if file exists
	if err := FileExists(path); err != nil {
		return err
	}

	// Check file size
	info, err := os.Stat(path)
	if err != nil {
		return NewFileReadError(path, err)
	}

	if info.Size() == 0 {
		return NewFileEmptyError(path)
	}

	if info.Size() > MaxFileSize {
		return NewFileTooLargeError(path, info.Size(), MaxFileSize)
	}

	return nil
}

// ValidateFileForWrite validates a path for writing
func ValidateFileForWrite(path string, overwrite bool) error {
	// Get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	// Check if file already exists
	info, err := os.Stat(absPath)
	if err == nil {
		// File exists
		if !overwrite {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("文件已存在: %s", path),
				Suggestion: "使用 --force 参数覆盖现有文件，或指定不同的输出路径",
			}
		}
		if info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("路径是目录而非文件"))
		}
	}

	// Check if parent directory exists and is writable
	parentDir := filepath.Dir(absPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("目录不存在: %s", parentDir),
				Suggestion: "请先创建目录或指定有效的输出路径",
			}
		}
		return NewFileWriteError(path, err)
	}

	if !parentInfo.IsDir() {
		return NewInvalidPathError(parentDir, fmt.Errorf("父路径不是目录"))
	}

	return nil
}

// ValidateKeyFile validates a key file
func ValidateKeyFile(path string, encoding EncodingType) error {
	// Check if file exists
	if err := FileExists(path); err != nil {
		return err
	}

	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		return NewKeyReadError(path, err)
	}

	// Check if file is empty
	if len(content) == 0 {
		return NewKeyCorruptedError(path, fmt.Errorf("文件为空"))
	}

	// Parse and validate key content
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 {
		return NewKeyCorruptedError(path, fmt.Errorf("文件格式无效"))
	}

	// Validate first line (should be a valid key)
	keyStr := strings.TrimSpace(lines[0])
	if keyStr == "" {
		return NewKeyCorruptedError(path, fmt.Errorf("密钥内容为空"))
	}

	// Try to decode the key to validate format
	_, err = DecodeKey(keyStr, encoding)
	if err != nil {
		return NewKeyInvalidFormatError(path, encoding.String(), err)
	}

	return nil
}

// DecodeKey decodes a key string with the specified encoding
func DecodeKey(keyStr string, encoding EncodingType) ([]byte, error) {
	var decoded []byte
	var err error

	switch encoding {
	case EncodingHex:
		decoded, err = hex.DecodeString(keyStr)
	case EncodingBase64:
		decoded, err = base64.StdEncoding.DecodeString(keyStr)
	case EncodingBase64URL:
		decoded, err = base64.URLEncoding.DecodeString(keyStr)
	default:
		decoded, err = hex.DecodeString(keyStr)
	}

	if err != nil {
		return nil, fmt.Errorf("解码失败: %w", err)
	}

	if len(decoded) != KeySize {
		return nil, NewKeyInvalidSizeError(KeySize, len(decoded))
	}

	return decoded, nil
}

// EncodeKey encodes a key with the specified encoding
func EncodeKey(key []byte, encoding EncodingType) string {
	switch encoding {
	case EncodingHex:
		return hex.EncodeToString(key)
	case EncodingBase64:
		return base64.StdEncoding.EncodeToString(key)
	case EncodingBase64URL:
		return base64.URLEncoding.EncodeToString(key)
	default:
		return hex.EncodeToString(key)
	}
}

// ReadFileContent reads file content with validation
func ReadFileContent(path string) ([]byte, error) {
	// Validate file for reading
	if err := ValidateFileForRead(path); err != nil {
		return nil, err
	}

	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, NewFileReadError(path, err)
	}

	return content, nil
}

// WriteFileContent writes content to a file with validation
func WriteFileContent(path string, content []byte, overwrite bool) error {
	// Validate file for writing
	if err := ValidateFileForWrite(path, overwrite); err != nil {
		return err
	}

	// Write file content
	err := os.WriteFile(path, content, 0644)
	if err != nil {
		return NewFileWriteError(path, err)
	}

	return nil
}

// EnsureDirectory ensures a directory exists, creating it if necessary
func EnsureDirectory(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	info, err := os.Stat(absPath)
	if err == nil {
		if !info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("路径是文件而非目录"))
		}
		return nil
	}

	if os.IsNotExist(err) {
		if err := os.MkdirAll(absPath, 0755); err != nil {
			return NewFileCreateError(path, err)
		}
		return nil
	}

	return NewFileCreateError(path, err)
}

// ValidateInputParameters validates common input parameters
func ValidateInputParameters(inputFile, text string) error {
	if inputFile == "" && text == "" {
		return NewMissingInputError("input")
	}
	if inputFile != "" && text != "" {
		return NewInvalidInputError("input", "不能同时指定 --input 和 --text")
	}
	return nil
}

// ValidateKeyParameters validates key parameters
func ValidateKeyParameters(publicKeyFile, privateKeyFile string, encoding EncodingType) error {
	// Validate public key file
	if publicKeyFile != "" {
		if err := ValidateKeyFile(publicKeyFile, encoding); err != nil {
			return err
		}
	}

	// Validate private key file
	if privateKeyFile != "" {
		if err := ValidateKeyFile(privateKeyFile, encoding); err != nil {
			return err
		}
	}

	return nil
}

// FormatFileSize formats a file size in bytes to a human-readable string
func FormatFileSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// GetFileInfo returns formatted file information
func GetFileInfo(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", NewFileReadError(path, err)
	}

	return fmt.Sprintf("%s (%s)", path, FormatFileSize(info.Size())), nil
}

// PrintSuccess prints a success message
func PrintSuccess(format string, args ...interface{}) {
	fmt.Printf("\n✓ %s\n", fmt.Sprintf(format, args...))
}

// PrintError prints an error message
func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\n✗ %s\n", fmt.Sprintf(format, args...))
}

// PrintWarning prints a warning message
func PrintWarning(format string, args ...interface{}) {
	fmt.Printf("\n⚠ %s\n", fmt.Sprintf(format, args...))
}

// PrintInfo prints an info message
func PrintInfo(format string, args ...interface{}) {
	fmt.Printf("\nℹ %s\n", fmt.Sprintf(format, args...))
}

// PrintQuestion prints a question message
func PrintQuestion(format string, args ...interface{}) {
	fmt.Printf("\n❓ %s ", fmt.Sprintf(format, args...))
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string, overwrite bool) error {
	if err := ValidateFileForRead(src); err != nil {
		return err
	}
	if err := ValidateFileForWrite(dst, overwrite); err != nil {
		return err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return NewFileReadError(src, err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return NewFileWriteError(dst, err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return NewFileWriteError(dst, err)
	}

	return nil
}

// FileExistsCheck checks if a file exists (returns boolean instead of error)
func FileExistsCheck(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, NewFileNotFoundError(path, err)
		}
		return 0, NewFileReadError(path, err)
	}
	if info.IsDir() {
		return 0, NewInvalidPathError(path, fmt.Errorf("路径是目录"))
	}
	return info.Size(), nil
}

// ComputeFileHash computes the SHA256 hash of a file
func ComputeFileHash(path string) (string, error) {
	if err := ValidateFileForRead(path); err != nil {
		return "", err
	}

	file, err := os.Open(path)
	if err != nil {
		return "", NewFileReadError(path, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", NewFileReadError(path, err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ReadLines reads all lines from a file
func ReadLines(path string) ([]string, error) {
	if err := ValidateFileForRead(path); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, NewFileReadError(path, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, NewFileReadError(path, err)
	}

	return lines, nil
}

// WriteLines writes lines to a file
func WriteLines(path string, lines []string, overwrite bool) error {
	if err := ValidateFileForWrite(path, overwrite); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return NewFileWriteError(path, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return NewFileWriteError(path, err)
		}
	}

	if err := writer.Flush(); err != nil {
		return NewFileWriteError(path, err)
	}

	return nil
}

// CreateBackup creates a backup of a file with .bak extension
func CreateBackup(path string) (string, error) {
	if err := ValidateFileForRead(path); err != nil {
		return "", err
	}

	backupPath := path + ".bak"
	if err := CopyFile(path, backupPath, true); err != nil {
		return "", NewFileCreateError(backupPath, err)
	}

	return backupPath, nil
}

// ValidateDirectory validates a directory for existence and write access
func ValidateDirectory(path string, createIfNotExists bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	info, err := os.Stat(absPath)
	if err == nil {
		if !info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("路径是文件而非目录"))
		}
		return nil
	}

	if os.IsNotExist(err) {
		if !createIfNotExists {
			return NewFileNotFoundError(path, err)
		}
		if err := os.MkdirAll(absPath, 0755); err != nil {
			return NewFileCreateError(path, err)
		}
		return nil
	}

	return NewFileReadError(path, err)
}

// SanitizeFileName removes invalid characters from a file name
func SanitizeFileName(name string) string {
	invalidChars := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range invalidChars {
		name = strings.ReplaceAll(name, char, "_")
	}
	return name
}

// GetRelativePath returns the relative path from base to target
func GetRelativePath(base, target string) (string, error) {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", NewInvalidPathError(base, err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", NewInvalidPathError(target, err)
	}
	return filepath.Rel(baseAbs, targetAbs)
}

// ValidateFilePath validates a file path for existence and readability
func ValidateFilePath(path string) error {
	if path == "" {
		return NewInvalidPathError(path, fmt.Errorf("路径为空"))
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return NewFileNotFoundError(path, err)
		}
		if os.IsPermission(err) {
			return NewFilePermissionError(path, err)
		}
		return NewFileReadError(path, err)
	}

	if info.IsDir() {
		return NewInvalidPathError(path, fmt.Errorf("路径是目录而非文件"))
	}

	return nil
}

// ValidateOutputPath validates an output path
func ValidateOutputPath(path string, overwrite bool) error {
	if path == "" {
		return NewInvalidPathError(path, fmt.Errorf("输出路径为空"))
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	info, err := os.Stat(absPath)
	if err == nil {
		if info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("路径是目录而非文件"))
		}
		if !overwrite {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("文件已存在: %s", path),
				Suggestion: "使用 --force 参数覆盖现有文件，或指定不同的输出路径",
			}
		}
	}

	parentDir := filepath.Dir(absPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("父目录不存在: %s", parentDir),
				Suggestion: "请先创建目录或指定有效的输出路径",
			}
		}
		return NewFileWriteError(path, err)
	}

	if !parentInfo.IsDir() {
		return NewInvalidPathError(parentDir, fmt.Errorf("父路径不是目录"))
	}

	return nil
}

// ValidateKeyData validates key data (32 bytes for Curve25519)
func ValidateKeyData(key []byte) error {
	if len(key) == 0 {
		return NewKeyCorruptedError("", fmt.Errorf("密钥数据为空"))
	}
	if len(key) != KeySize {
		return NewKeyInvalidSizeError(KeySize, len(key))
	}
	return nil
}

// ValidateHexString validates a hexadecimal string
func ValidateHexString(hexStr string) error {
	if hexStr == "" {
		return NewInvalidInputError("hex", "字符串为空")
	}
	if len(hexStr)%2 != 0 {
		return NewInvalidInputError("hex", "长度必须是偶数")
	}
	for _, c := range strings.ToLower(hexStr) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return NewInvalidInputError("hex", fmt.Sprintf("包含无效字符 '%c'", c))
		}
	}
	return nil
}

// ValidateBase64String validates a base64 string
func ValidateBase64String(base64Str string) error {
	if base64Str == "" {
		return NewInvalidInputError("base64", "字符串为空")
	}
	_, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return NewInvalidInputError("base64", fmt.Sprintf("解码失败: %v", err))
	}
	return nil
}

// ValidateBase64URLString validates a base64 URL-safe string
func ValidateBase64URLString(base64URLStr string) error {
	if base64URLStr == "" {
		return NewInvalidInputError("base64url", "字符串为空")
	}
	_, err := base64.URLEncoding.DecodeString(base64URLStr)
	if err != nil {
		return NewInvalidInputError("base64url", fmt.Sprintf("解码失败: %v", err))
	}
	return nil
}

// ValidateKeyFormat validates a key string based on encoding type
func ValidateKeyFormat(keyStr string, encoding EncodingType) error {
	if keyStr == "" {
		return NewInvalidInputError("key", "密钥字符串为空")
	}

	switch encoding {
	case EncodingHex:
		return ValidateHexString(keyStr)
	case EncodingBase64:
		return ValidateBase64String(keyStr)
	case EncodingBase64URL:
		return ValidateBase64URLString(keyStr)
	default:
		return NewInvalidEncodingError(encoding.String(), []string{"hex", "base64", "base64url"})
	}
}

// ValidateEncryptedData validates encrypted data format
func ValidateEncryptedData(data []byte, minSize int) error {
	if len(data) == 0 {
		return NewInvalidCiphertextError("数据为空")
	}
	if len(data) < minSize {
		return NewInvalidCiphertextError(fmt.Sprintf("数据长度不足，期望至少 %d 字节，实际 %d 字节", minSize, len(data)))
	}
	return nil
}

// IsNeptuneEncryptedFile checks if a file is already encrypted with Neptune
// It checks: 1) file extension is .ntp, 2) file size is at least minimum header size
func IsNeptuneEncryptedFile(filePath string) (bool, error) {
	// Check file extension first (fast check)
	if strings.HasSuffix(strings.ToLower(filePath), NeptuneFileExtension) {
		return true, nil
	}

	// Check file header for Neptune format
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, NewFileNotFoundError(filePath, err)
		}
		return false, NewFileReadError(filePath, err)
	}

	// File is too small to be a valid Neptune encrypted file
	if info.Size() < NeptuneMinHeaderSize {
		return false, nil
	}

	// Read file header to check for Neptune format
	file, err := os.Open(filePath)
	if err != nil {
		return false, NewFileReadError(filePath, err)
	}
	defer file.Close()

	header := make([]byte, NeptuneMinHeaderSize)
	n, err := file.Read(header)
	if err != nil {
		return false, NewFileReadError(filePath, err)
	}

	// Check if we read the full header
	if n < NeptuneMinHeaderSize {
		return false, nil
	}

	// Check version byte (currently version 1)
	// Version byte is the first byte in the header
	if header[0] == 0x01 {
		return true, nil
	}

	return false, nil
}

// ValidateNotEncrypted checks if a file is NOT already encrypted
// Returns error if file is already encrypted (unless forceOverride is true)
func ValidateNotEncrypted(filePath string, forceOverride bool) error {
	isEncrypted, err := IsNeptuneEncryptedFile(filePath)
	if err != nil {
		return err
	}

	if isEncrypted {
		if forceOverride {
			return nil
		}
		return &NeptuneError{
			Code:       ErrCodeFileAlreadyEncrypted,
			Message:    fmt.Sprintf("文件已加密: %s", filePath),
			Suggestion: "使用 --force-override 参数强制加密，或检查输入文件",
		}
	}

	return nil
}

// ValidateVersion validates the encryption format version
func ValidateVersion(version byte, supportedVersions []byte) error {
	for _, v := range supportedVersions {
		if version == v {
			return nil
		}
	}
	return NewInvalidVersionError(version)
}

// ValidateNonce validates a nonce (should be 16 bytes for Sosemanuk)
func ValidateNonce(nonce []byte, expectedSize int) error {
	if len(nonce) == 0 {
		return NewInvalidInputError("nonce", "nonce 为空")
	}
	if len(nonce) != expectedSize {
		return NewInvalidInputError("nonce", fmt.Sprintf("长度无效，期望 %d 字节，实际 %d 字节", expectedSize, len(nonce)))
	}
	return nil
}

// ValidateParameterNotEmpty validates that a parameter is not empty
func ValidateParameterNotEmpty(paramName, value string) error {
	if value == "" {
		return NewMissingInputError(paramName)
	}
	return nil
}

// ValidateParameterInRange validates that an integer parameter is within a range
func ValidateParameterInRange(paramName string, value, min, max int) error {
	if value < min || value > max {
		return NewInvalidParameterError(paramName, fmt.Sprintf("%d", value), fmt.Sprintf("必须在 %d 到 %d 之间", min, max))
	}
	return nil
}

// ValidateParameterPositive validates that an integer parameter is positive
func ValidateParameterPositive(paramName string, value int) error {
	if value <= 0 {
		return NewInvalidParameterError(paramName, fmt.Sprintf("%d", value), "必须为正数")
	}
	return nil
}

// ValidateParameterPositive64 validates that an int64 parameter is positive
func ValidateParameterPositive64(paramName string, value int64) error {
	if value <= 0 {
		return NewInvalidParameterError(paramName, fmt.Sprintf("%d", value), "必须为正数")
	}
	return nil
}

// ValidateFilePathIsWritable validates that a file path is writable
func ValidateFilePathIsWritable(path string) error {
	if path == "" {
		return NewInvalidPathError(path, fmt.Errorf("路径为空"))
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	parentDir := filepath.Dir(absPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return NewFileNotFoundError(parentDir, err)
		}
		return NewFileReadError(parentDir, err)
	}

	if !parentInfo.IsDir() {
		return NewInvalidPathError(parentDir, fmt.Errorf("父路径不是目录"))
	}

	testFile := filepath.Join(parentDir, ".neptune_test_write.tmp")
	f, err := os.Create(testFile)
	if err != nil {
		return NewFilePermissionError(parentDir, err)
	}
	f.Close()
	os.Remove(testFile)

	return nil
}

// ValidateKeyPairConsistency validates that private and public keys have correct sizes
// Note: Full consistency validation requires Curve25519 operations which is done in curve25519 package
func ValidateKeyPairConsistency(privateKey, publicKey []byte) error {
	if err := ValidateKeyData(privateKey); err != nil {
		return err
	}
	if err := ValidateKeyData(publicKey); err != nil {
		return err
	}
	return nil
}

// ValidateInputData validates input data for encryption/decryption
func ValidateInputData(data []byte, operation string) error {
	if len(data) == 0 {
		return NewInvalidInputError(operation, "输入数据为空")
	}
	return nil
}

// ValidateEncodingFormat validates an encoding format string
func ValidateEncodingFormat(encoding string) error {
	_, err := ParseEncodingType(encoding)
	return err
}

// ValidateAllParameters validates all input parameters at once
func ValidateAllParameters(params map[string]interface{}) []error {
	var errs []error

	for name, value := range params {
		switch v := value.(type) {
		case string:
			if v == "" {
				errs = append(errs, NewMissingInputError(name))
			}
		case int:
			if v <= 0 {
				errs = append(errs, NewInvalidParameterError(name, fmt.Sprintf("%d", v), "必须为正数"))
			}
		case int64:
			if v <= 0 {
				errs = append(errs, NewInvalidParameterError(name, fmt.Sprintf("%d", v), "必须为正数"))
			}
		case []byte:
			if len(v) == 0 {
				errs = append(errs, NewInvalidInputError(name, "数据为空"))
			}
		case nil:
			errs = append(errs, NewMissingInputError(name))
		}
	}

	return errs
}

// FindFilesRecursively finds all files in a directory recursively
func FindFilesRecursively(dirPath string, includePatterns, excludePatterns []string) ([]string, error) {
	var files []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return NewFileReadError(path, err)
		}

		if info.IsDir() {
			return nil
		}

		// Check exclude patterns first
		for _, pattern := range excludePatterns {
			if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
				return nil
			}
		}

		// Check include patterns if specified
		if len(includePatterns) > 0 {
			matched := false
			for _, pattern := range includePatterns {
				if match, _ := filepath.Match(pattern, filepath.Base(path)); match {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		}

		files = append(files, path)
		return nil
	})

	if err != nil {
		return nil, NewFileReadError(dirPath, err)
	}

	return files, nil
}

// GetRelativePathFromBase returns the relative path from a base directory
func GetRelativePathFromBase(base, target string) (string, error) {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", NewInvalidPathError(base, err)
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", NewInvalidPathError(target, err)
	}
	return filepath.Rel(baseAbs, targetAbs)
}

// EnsureParentDirectory ensures the parent directory of a file path exists
func EnsureParentDirectory(filePath string) error {
	parentDir := filepath.Dir(filePath)
	if parentDir == "." || parentDir == "/" || parentDir == "\\" {
		return nil
	}
	return EnsureDirectory(parentDir)
}

// CopyDirectoryRecursively copies a directory recursively
func CopyDirectoryRecursively(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return NewFileReadError(src, err)
	}

	if !srcInfo.IsDir() {
		return NewInvalidPathError(src, fmt.Errorf("源路径不是目录"))
	}

	if err := EnsureDirectory(dst); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return NewFileReadError(src, err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := CopyDirectoryRecursively(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := CopyFile(srcPath, dstPath, true); err != nil {
				return err
			}
		}
	}

	return nil
}

// DeleteEmptyDirectories deletes empty directories recursively
func DeleteEmptyDirectories(dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return NewFileReadError(dirPath, err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(dirPath, entry.Name())
		if entry.IsDir() {
			if err := DeleteEmptyDirectories(entryPath); err != nil {
				return err
			}
		}
	}

	// Check if directory is now empty
	entries, err = os.ReadDir(dirPath)
	if err != nil {
		return NewFileReadError(dirPath, err)
	}

	if len(entries) == 0 {
		if err := os.Remove(dirPath); err != nil {
			return NewFileDeleteError(dirPath, err)
		}
	}

	return nil
}

// DefaultHTTPTimeout is the default timeout for HTTP requests
const DefaultHTTPTimeout = 30 * time.Second

// IsHTTPURL checks if a string is an HTTP or HTTPS URL
func IsHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// DownloadFile downloads a file from a URL to a local file
func DownloadFile(urlStr, outputPath string, timeout time.Duration) error {
	if !IsHTTPURL(urlStr) {
		return NewInvalidInputError("url", "无效的 HTTP/HTTPS URL")
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		return NewFileReadError(urlStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &NeptuneError{
			Code:   ErrCodeFileReadFailed,
			Message: fmt.Sprintf("下载失败: HTTP %d", resp.StatusCode),
			Suggestion: "请检查 URL 是否正确，确保资源可访问",
		}
	}

	// Ensure parent directory exists
	if err := EnsureParentDirectory(outputPath); err != nil {
		return err
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return NewFileWriteError(outputPath, err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return NewFileWriteError(outputPath, err)
	}

	return nil
}

// DownloadToTempFile downloads a file from URL to a temporary file and returns the path
func DownloadToTempFile(urlStr string, timeout time.Duration) (string, error) {
	if !IsHTTPURL(urlStr) {
		return "", NewInvalidInputError("url", "无效的 HTTP/HTTPS URL")
	}

	tempFile, err := os.CreateTemp("", "neptune_*.tmp")
	if err != nil {
		return "", NewFileCreateError("", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()

	if err := DownloadFile(urlStr, tempPath, timeout); err != nil {
		os.Remove(tempPath)
		return "", err
	}

	return tempPath, nil
}

// DownloadBytes downloads data from a URL and returns it as bytes
func DownloadBytes(urlStr string, timeout time.Duration) ([]byte, error) {
	if !IsHTTPURL(urlStr) {
		return nil, NewInvalidInputError("url", "无效的 HTTP/HTTPS URL")
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, NewFileReadError(urlStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &NeptuneError{
			Code:   ErrCodeFileReadFailed,
			Message: fmt.Sprintf("下载失败: HTTP %d", resp.StatusCode),
			Suggestion: "请检查 URL 是否正确，确保资源可访问",
		}
	}

	return io.ReadAll(resp.Body)
}

// ExtractFileNameFromURL extracts the filename from a URL
func ExtractFileNameFromURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "downloaded"
	}
	path := u.Path
	filename := filepath.Base(path)
	if filename == "." || filename == "/" || filename == "" {
		return "downloaded"
	}
	return filename
}