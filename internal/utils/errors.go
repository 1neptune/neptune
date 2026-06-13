// Package utils provides common utilities for the Neptune encryption tool
package utils

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// NeptuneError represents a structured error with user-friendly messages
type NeptuneError struct {
	Code        string // Error code for programmatic handling
	Message     string // User-friendly error message
	Cause       error  // Underlying error
	Suggestion  string // Suggested action to resolve the error
}

// Error implements the error interface
func (e *NeptuneError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap implements the errors.Unwrap interface
func (e *NeptuneError) Unwrap() error {
	return e.Cause
}

// FullError returns the complete error with suggestion
func (e *NeptuneError) FullError() string {
	var result string
	if e.Cause != nil {
		result = fmt.Sprintf("错误: %s\n原因: %v", e.Message, e.Cause)
	} else {
		result = fmt.Sprintf("错误: %s", e.Message)
	}
	if e.Suggestion != "" {
		result += fmt.Sprintf("\n建议: %s", e.Suggestion)
	}
	return result
}

// Error codes
const (
	// File operation errors
	ErrCodeFileNotFound         = "FILE_NOT_FOUND"
	ErrCodeFileReadFailed       = "FILE_READ_FAILED"
	ErrCodeFileWriteFailed      = "FILE_WRITE_FAILED"
	ErrCodeFileCreateFailed     = "FILE_CREATE_FAILED"
	ErrCodeFilePermission       = "FILE_PERMISSION"
	ErrCodeFileTooLarge         = "FILE_TOO_LARGE"
	ErrCodeFileEmpty            = "FILE_EMPTY"
	ErrCodeFileAlreadyEncrypted = "FILE_ALREADY_ENCRYPTED"
	ErrCodeInvalidPath          = "INVALID_PATH"

	// Key errors
	ErrCodeKeyNotFound       = "KEY_NOT_FOUND"
	ErrCodeKeyReadFailed     = "KEY_READ_FAILED"
	ErrCodeKeyWriteFailed    = "KEY_WRITE_FAILED"
	ErrCodeKeyInvalidFormat  = "KEY_INVALID_FORMAT"
	ErrCodeKeyInvalidSize    = "KEY_INVALID_SIZE"
	ErrCodeKeyCorrupted      = "KEY_CORRUPTED"
	ErrCodeKeyMismatch       = "KEY_MISMATCH"

	// Encryption/Decryption errors
	ErrCodeEncryptFailed    = "ENCRYPT_FAILED"
	ErrCodeDecryptFailed    = "DECRYPT_FAILED"
	ErrCodeInvalidVersion   = "INVALID_VERSION"
	ErrCodeInvalidCiphertext = "INVALID_CIPHERTEXT"
	ErrCodeInvalidNonce     = "INVALID_NONCE"

	// Input validation errors
	ErrCodeInvalidInput     = "INVALID_INPUT"
	ErrCodeMissingInput     = "MISSING_INPUT"
	ErrCodeInvalidEncoding  = "INVALID_ENCODING"
	ErrCodeInvalidParameter = "INVALID_PARAMETER"
)

// NewFileNotFoundError creates a file not found error
func NewFileNotFoundError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileNotFound,
		Message: fmt.Sprintf("文件不存在: %s", path),
		Cause:  cause,
		Suggestion: "请检查文件路径是否正确，确保文件存在",
	}
}

// NewFileReadError creates a file read error
func NewFileReadError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileReadFailed,
		Message: fmt.Sprintf("无法读取文件: %s", path),
		Cause:  cause,
		Suggestion: "请检查文件权限，确保有读取权限",
	}
}

// NewFileWriteError creates a file write error
func NewFileWriteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileWriteFailed,
		Message: fmt.Sprintf("无法写入文件: %s", path),
		Cause:  cause,
		Suggestion: "请检查文件权限和磁盘空间，确保有写入权限",
	}
}

// NewFileCreateError creates a file creation error
func NewFileCreateError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileCreateFailed,
		Message: fmt.Sprintf("无法创建文件: %s", path),
		Cause:  cause,
		Suggestion: "请检查目录权限和磁盘空间",
	}
}

// NewFilePermissionError creates a file permission error
func NewFilePermissionError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFilePermission,
		Message: fmt.Sprintf("文件权限不足: %s", path),
		Cause:  cause,
		Suggestion: "请以管理员权限运行或检查文件权限设置",
	}
}

// NewFileTooLargeError creates a file too large error
func NewFileTooLargeError(path string, size, maxSize int64) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileTooLarge,
		Message: fmt.Sprintf("文件过大: %s (大小: %d 字节, 最大允许: %d 字节)", path, size, maxSize),
		Suggestion: "请使用分块加密或选择较小的文件",
	}
}

// NewFileEmptyError creates an empty file error
func NewFileEmptyError(path string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileEmpty,
		Message: fmt.Sprintf("文件为空: %s", path),
		Suggestion: "请确保文件包含有效内容",
	}
}

// NewFileDeleteError creates a file delete error
func NewFileDeleteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileWriteFailed,
		Message: fmt.Sprintf("无法删除文件: %s", path),
		Cause:  cause,
		Suggestion: "请检查文件权限，确保有删除权限",
	}
}

// NewInvalidPathError creates an invalid path error
func NewInvalidPathError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidPath,
		Message: fmt.Sprintf("无效的文件路径: %s", path),
		Cause:  cause,
		Suggestion: "请检查路径格式是否正确",
	}
}

// NewKeyNotFoundError creates a key not found error
func NewKeyNotFoundError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyNotFound,
		Message: fmt.Sprintf("密钥文件不存在: %s", path),
		Cause:  cause,
		Suggestion: "请使用 'neptune keygen' 命令生成密钥对",
	}
}

// NewKeyReadError creates a key read error
func NewKeyReadError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyReadFailed,
		Message: fmt.Sprintf("无法读取密钥文件: %s", path),
		Cause:  cause,
		Suggestion: "请检查文件权限和文件格式",
	}
}

// NewKeyWriteError creates a key write error
func NewKeyWriteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyWriteFailed,
		Message: fmt.Sprintf("无法写入密钥文件: %s", path),
		Cause:  cause,
		Suggestion: "请检查目录权限和磁盘空间",
	}
}

// NewKeyInvalidFormatError creates an invalid key format error
func NewKeyInvalidFormatError(path, encoding string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyInvalidFormat,
		Message: fmt.Sprintf("密钥格式无效: %s (编码: %s)", path, encoding),
		Cause:  cause,
		Suggestion: fmt.Sprintf("请确保密钥文件使用正确的编码格式 (%s)", encoding),
	}
}

// NewKeyInvalidSizeError creates an invalid key size error
func NewKeyInvalidSizeError(expectedSize, actualSize int) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyInvalidSize,
		Message: fmt.Sprintf("密钥大小无效: 期望 %d 字节, 实际 %d 字节", expectedSize, actualSize),
		Suggestion: "请确保密钥文件未被损坏或修改",
	}
}

// NewKeyCorruptedError creates a corrupted key error
func NewKeyCorruptedError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyCorrupted,
		Message: fmt.Sprintf("密钥文件已损坏: %s", path),
		Cause:  cause,
		Suggestion: "请重新生成密钥对或从备份恢复",
	}
}

// NewKeyMismatchError creates a key mismatch error
func NewKeyMismatchError() *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyMismatch,
		Message: "私钥与公钥不匹配",
		Suggestion: "请确保使用正确的密钥对进行解密",
	}
}

// NewEncryptError creates an encryption error
func NewEncryptError(cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeEncryptFailed,
		Message: "加密失败",
		Cause:  cause,
		Suggestion: "请检查密钥是否正确，数据是否有效",
	}
}

// NewDecryptError creates a decryption error
func NewDecryptError(cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeDecryptFailed,
		Message: "解密失败",
		Cause:  cause,
		Suggestion: "请确保使用正确的私钥，且数据未被篡改",
	}
}

// NewInvalidVersionError creates an invalid version error
func NewInvalidVersionError(version byte) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidVersion,
		Message: fmt.Sprintf("不支持的数据版本: %d", version),
		Suggestion: "请确保使用最新版本的 Neptune 工具",
	}
}

// NewInvalidCiphertextError creates an invalid ciphertext error
func NewInvalidCiphertextError(reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidCiphertext,
		Message: fmt.Sprintf("无效的密文数据: %s", reason),
		Suggestion: "请确保数据未被损坏或篡改",
	}
}

// NewInvalidInputError creates an invalid input error
func NewInvalidInputError(param, reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidInput,
		Message: fmt.Sprintf("无效的输入参数 '%s': %s", param, reason),
		Suggestion: "请检查输入参数是否正确",
	}
}

// NewMissingInputError creates a missing input error
func NewMissingInputError(param string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeMissingInput,
		Message: fmt.Sprintf("缺少必需的参数: %s", param),
		Suggestion: fmt.Sprintf("请使用 --%s 参数指定", param),
	}
}

// NewInvalidEncodingError creates an invalid encoding error
func NewInvalidEncodingError(encoding string, supported []string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidEncoding,
		Message: fmt.Sprintf("不支持的编码格式: %s", encoding),
		Suggestion: fmt.Sprintf("支持的编码格式: %v", supported),
	}
}

// NewInvalidParameterError creates an invalid parameter error
func NewInvalidParameterError(param, value, reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidParameter,
		Message: fmt.Sprintf("参数 '%s' 的值 '%s' 无效: %s", param, value, reason),
		Suggestion: "请检查参数值是否符合要求",
	}
}

// IsNeptuneError checks if an error is a NeptuneError
func IsNeptuneError(err error) bool {
	var ne *NeptuneError
	return errors.As(err, &ne)
}

// GetNeptuneError extracts NeptuneError from an error
func GetNeptuneError(err error) *NeptuneError {
	var ne *NeptuneError
	if errors.As(err, &ne) {
		return ne
	}
	return nil
}

// WrapError wraps a standard error into a NeptuneError with context
func WrapError(err error, code, message, suggestion string) *NeptuneError {
	return &NeptuneError{
		Code:       code,
		Message:    message,
		Cause:      err,
		Suggestion: suggestion,
	}
}

// NewDecryptKeyMismatchError creates a key mismatch error for decryption
func NewDecryptKeyMismatchError() *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeKeyMismatch,
		Message:    "密钥不匹配：无法使用提供的私钥解密数据",
		Suggestion: "请确保使用正确的私钥，该私钥应与加密时使用的公钥配对",
	}
}

// NewHashMismatchError creates a hash mismatch error
func NewHashMismatchError(expected, actual string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidCiphertext,
		Message:    fmt.Sprintf("数据完整性校验失败: 期望哈希 %s, 实际哈希 %s", expected, actual),
		Suggestion: "数据可能已被篡改或损坏",
	}
}

// NewNotEnoughMemoryError creates a memory error
func NewNotEnoughMemoryError(size int64) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("内存不足：无法处理大小为 %d 字节的数据", size),
		Suggestion: "请尝试处理较小的文件或增加系统可用内存",
	}
}

// NewInvalidStateError creates an invalid state error
func NewInvalidStateError(message string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("无效状态: %s", message),
		Suggestion: "请检查操作顺序或系统状态",
	}
}

// NewOperationNotSupportedError creates an operation not supported error
func NewOperationNotSupportedError(operation string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("不支持的操作: %s", operation),
		Suggestion: "请使用其他方法或升级到最新版本",
	}
}

// NewConversionError creates a conversion error
func NewConversionError(from, to string, err error) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("转换失败: %s -> %s", from, to),
		Cause:      err,
		Suggestion: "请确保数据格式正确",
	}
}

// NewDependencyError creates a dependency error
func NewDependencyError(dep string, err error) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("依赖组件错误: %s", dep),
		Cause:      err,
		Suggestion: "请检查依赖是否正确安装或配置",
	}
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(operation string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("操作超时: %s", operation),
		Suggestion: "请重试操作或增加超时时间",
	}
}

// NewResourceExhaustedError creates a resource exhausted error
func NewResourceExhaustedError(resource string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("资源耗尽: %s", resource),
		Suggestion: "请释放资源后重试",
	}
}

// PrintErrorWithCode prints an error with its code
func (e *NeptuneError) PrintErrorWithCode() {
	fmt.Printf("\n✗ [%s] %s\n", e.Code, e.Message)
	if e.Cause != nil {
		fmt.Printf("  原因: %v\n", e.Cause)
	}
	if e.Suggestion != "" {
		fmt.Printf("  建议: %s\n", e.Suggestion)
	}
}

// PrintDetailed prints a detailed error report
func (e *NeptuneError) PrintDetailed() {
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Printf("错误代码: %s\n", e.Code)
	fmt.Printf("错误消息: %s\n", e.Message)
	if e.Cause != nil {
		fmt.Printf("底层原因: %v\n", e.Cause)
	}
	if e.Suggestion != "" {
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Printf("解决方案: %s\n", e.Suggestion)
	}
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// IsErrorType checks if the error matches a specific error code
func IsErrorType(err error, code string) bool {
	var ne *NeptuneError
	if errors.As(err, &ne) {
		return ne.Code == code
	}
	return false
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) string {
	var ne *NeptuneError
	if errors.As(err, &ne) {
		return ne.Code
	}
	return ""
}

// FormatErrorList formats multiple errors into a readable string
func FormatErrorList(errs []error) string {
	var messages []string
	for i, err := range errs {
		if ne := GetNeptuneError(err); ne != nil {
			messages = append(messages, fmt.Sprintf("%d. [%s] %s", i+1, ne.Code, ne.Message))
		} else {
			messages = append(messages, fmt.Sprintf("%d. %v", i+1, err))
		}
	}
	return strings.Join(messages, "\n")
}

// AggregateErrors aggregates multiple errors into one
func AggregateErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}

	var messages []string
	for _, err := range errs {
		messages = append(messages, err.Error())
	}

	return &NeptuneError{
		Code:    ErrCodeInvalidInput,
		Message: fmt.Sprintf("发现多个错误:\n%s", strings.Join(messages, "\n")),
	}
}

// HandleError handles an error by checking if it's a NeptuneError and printing appropriate messages
func HandleError(err error) {
	if err == nil {
		return
	}

	if ne := GetNeptuneError(err); ne != nil {
		ne.PrintDetailed()
	} else {
		fmt.Fprintf(os.Stderr, "\n✗ 未知错误: %v\n", err)
	}
}

// Must checks if an error is not nil and panics if so
func Must(err error) {
	if err != nil {
		if ne := GetNeptuneError(err); ne != nil {
			panic(ne.FullError())
		}
		panic(err)
	}
}

// IgnoreError ignores an error (useful for optional operations)
func IgnoreError(err error) {}

// SuppressError suppresses specific error types
func SuppressError(err error, codes ...string) error {
	if err == nil {
		return nil
	}

	if ne := GetNeptuneError(err); ne != nil {
		for _, code := range codes {
			if ne.Code == code {
				return nil
			}
		}
	}

	return err
}