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
		result = fmt.Sprintf(": %s\n: %v", e.Message, e.Cause)
	} else {
		result = fmt.Sprintf(": %s", e.Message)
	}
	if e.Suggestion != "" {
		result += fmt.Sprintf("\n: %s", e.Suggestion)
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
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewFileReadError creates a file read error
func NewFileReadError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileReadFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewFileWriteError creates a file write error
func NewFileWriteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileWriteFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewFileCreateError creates a file creation error
func NewFileCreateError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileCreateFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewFilePermissionError creates a file permission error
func NewFilePermissionError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFilePermission,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewFileTooLargeError creates a file too large error
func NewFileTooLargeError(path string, size, maxSize int64) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileTooLarge,
		Message: fmt.Sprintf(": %s (: %d , : %d )", path, size, maxSize),
		Suggestion: "",
	}
}

// NewFileEmptyError creates an empty file error
func NewFileEmptyError(path string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileEmpty,
		Message: fmt.Sprintf(": %s", path),
		Suggestion: "",
	}
}

// NewFileDeleteError creates a file delete error
func NewFileDeleteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileWriteFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewInvalidPathError creates an invalid path error
func NewInvalidPathError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidPath,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyNotFoundError creates a key not found error
func NewKeyNotFoundError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyNotFound,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: " 'neptune keygen' ",
	}
}

// NewKeyReadError creates a key read error
func NewKeyReadError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyReadFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyWriteError creates a key write error
func NewKeyWriteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyWriteFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyInvalidFormatError creates an invalid key format error
func NewKeyInvalidFormatError(path, encoding string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyInvalidFormat,
		Message: fmt.Sprintf(": %s (: %s)", path, encoding),
		Cause:  cause,
		Suggestion: fmt.Sprintf(" (%s)", encoding),
	}
}

// NewKeyInvalidSizeError creates an invalid key size error
func NewKeyInvalidSizeError(expectedSize, actualSize int) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyInvalidSize,
		Message: fmt.Sprintf(":  %d ,  %d ", expectedSize, actualSize),
		Suggestion: "",
	}
}

// NewKeyCorruptedError creates a corrupted key error
func NewKeyCorruptedError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyCorrupted,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyMismatchError creates a key mismatch error
func NewKeyMismatchError() *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyMismatch,
		Message: "",
		Suggestion: "",
	}
}

// NewEncryptError creates an encryption error
func NewEncryptError(cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeEncryptFailed,
		Message: "",
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewDecryptError creates a decryption error
func NewDecryptError(cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeDecryptFailed,
		Message: "",
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewInvalidVersionError creates an invalid version error
func NewInvalidVersionError(version byte) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidVersion,
		Message: fmt.Sprintf(": %d", version),
		Suggestion: " Neptune ",
	}
}

// NewInvalidCiphertextError creates an invalid ciphertext error
func NewInvalidCiphertextError(reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidCiphertext,
		Message: fmt.Sprintf(": %s", reason),
		Suggestion: "",
	}
}

// NewInvalidInputError creates an invalid input error
func NewInvalidInputError(param, reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidInput,
		Message: fmt.Sprintf(" '%s': %s", param, reason),
		Suggestion: "",
	}
}

// NewMissingInputError creates a missing input error
func NewMissingInputError(param string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeMissingInput,
		Message: fmt.Sprintf(": %s", param),
		Suggestion: fmt.Sprintf(" --%s ", param),
	}
}

// NewInvalidEncodingError creates an invalid encoding error
func NewInvalidEncodingError(encoding string, supported []string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidEncoding,
		Message: fmt.Sprintf(": %s", encoding),
		Suggestion: fmt.Sprintf(": %v", supported),
	}
}

// NewInvalidParameterError creates an invalid parameter error
func NewInvalidParameterError(param, value, reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidParameter,
		Message: fmt.Sprintf(" '%s'  '%s' : %s", param, value, reason),
		Suggestion: "",
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
		Message:    "：",
		Suggestion: "，",
	}
}

// NewHashMismatchError creates a hash mismatch error
func NewHashMismatchError(expected, actual string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidCiphertext,
		Message:    fmt.Sprintf(":  %s,  %s", expected, actual),
		Suggestion: "",
	}
}

// NewNotEnoughMemoryError creates a memory error
func NewNotEnoughMemoryError(size int64) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("： %d ", size),
		Suggestion: "",
	}
}

// NewInvalidStateError creates an invalid state error
func NewInvalidStateError(message string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", message),
		Suggestion: "",
	}
}

// NewOperationNotSupportedError creates an operation not supported error
func NewOperationNotSupportedError(operation string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", operation),
		Suggestion: "",
	}
}

// NewConversionError creates a conversion error
func NewConversionError(from, to string, err error) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s -> %s", from, to),
		Cause:      err,
		Suggestion: "",
	}
}

// NewDependencyError creates a dependency error
func NewDependencyError(dep string, err error) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", dep),
		Cause:      err,
		Suggestion: "",
	}
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(operation string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", operation),
		Suggestion: "",
	}
}

// NewResourceExhaustedError creates a resource exhausted error
func NewResourceExhaustedError(resource string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", resource),
		Suggestion: "",
	}
}

// PrintErrorWithCode prints an error with its code
func (e *NeptuneError) PrintErrorWithCode() {
	fmt.Printf("\n✗ [%s] %s\n", e.Code, e.Message)
	if e.Cause != nil {
		fmt.Printf("  : %v\n", e.Cause)
	}
	if e.Suggestion != "" {
		fmt.Printf("  : %s\n", e.Suggestion)
	}
}

// PrintDetailed prints a detailed error report
func (e *NeptuneError) PrintDetailed() {
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Printf(": %s\n", e.Code)
	fmt.Printf(": %s\n", e.Message)
	if e.Cause != nil {
		fmt.Printf(": %v\n", e.Cause)
	}
	if e.Suggestion != "" {
		fmt.Println("───────────────────────────────────────────────────────────────")
		fmt.Printf(": %s\n", e.Suggestion)
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
		Message: fmt.Sprintf(":\n%s", strings.Join(messages, "\n")),
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
		fmt.Fprintf(os.Stderr, "\n✗ : %v\n", err)
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