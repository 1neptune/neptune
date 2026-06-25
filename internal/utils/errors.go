// Package utils provides common utility functions and types for the Neptune encryption tool.
// This package includes error handling, secure memory management, disk utilities,
// and other shared functionality used across the Neptune codebase.
package utils

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// NeptuneError represents a structured error type with user-friendly messages
// and additional context for error handling. It implements the standard error
// interface and provides support for error wrapping via the Unwrap method.
//
// Fields:
//   - Code:        A machine-readable error code for programmatic error handling
//   - Message:     A human-readable error message describing what went wrong
//   - Cause:       The underlying error that caused this error (may be nil)
//   - Suggestion:  A suggested action the user can take to resolve the error
type NeptuneError struct {
	Code        string // Error code for programmatic handling and categorization
	Message     string // User-facing error message describing the problem
	Cause       error  // Underlying/wrapped error that caused this error (nil if none)
	Suggestion  string // Recommended action to help the user resolve the issue
}

// Error implements the standard error interface for NeptuneError.
// It returns a string containing the error message and, if present,
// the underlying cause error in the format "Message: Cause".
//
// Returns:
//   - A string representation of the error including the cause if available.
func (e *NeptuneError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap implements the errors.Unwrap interface, enabling error chain
// traversal with errors.Is, errors.As, and errors.Unwrap.
//
// Returns:
//   - The underlying cause error, or nil if no cause is set.
func (e *NeptuneError) Unwrap() error {
	return e.Cause
}

// FullError returns the complete error string including the suggestion
// for how to resolve the issue. Currently returns an empty string and
// is intended to be implemented for full error reporting.
//
// Returns:
//   - A complete error message with suggestion (currently empty).
func (e *NeptuneError) FullError() string {
	return ""
}

// Error codes define machine-readable identifiers for different error types.
// These codes enable programmatic error handling and categorization.
const (
	// File operation errors - errors related to file system operations
	ErrCodeFileNotFound         = "FILE_NOT_FOUND"         // The specified file does not exist
	ErrCodeFileReadFailed       = "FILE_READ_FAILED"       // Failed to read from a file
	ErrCodeFileWriteFailed      = "FILE_WRITE_FAILED"      // Failed to write to a file
	ErrCodeFileCreateFailed     = "FILE_CREATE_FAILED"     // Failed to create a new file
	ErrCodeFilePermission       = "FILE_PERMISSION"        // Insufficient permissions for file operation
	ErrCodeFileTooLarge         = "FILE_TOO_LARGE"         // File exceeds the maximum allowed size
	ErrCodeFileEmpty            = "FILE_EMPTY"             // File is empty when content was expected
	ErrCodeFileAlreadyEncrypted = "FILE_ALREADY_ENCRYPTED" // File has already been encrypted by Neptune
	ErrCodeInvalidPath          = "INVALID_PATH"           // The provided file path is invalid

	// Key errors - errors related to encryption key management
	ErrCodeKeyNotFound       = "KEY_NOT_FOUND"       // The encryption key file was not found
	ErrCodeKeyReadFailed     = "KEY_READ_FAILED"     // Failed to read the key file
	ErrCodeKeyWriteFailed    = "KEY_WRITE_FAILED"    // Failed to write the key file
	ErrCodeKeyInvalidFormat  = "KEY_INVALID_FORMAT"  // Key file has an unrecognized format
	ErrCodeKeyInvalidSize    = "KEY_INVALID_SIZE"    // Key size does not match expected length
	ErrCodeKeyCorrupted      = "KEY_CORRUPTED"       // Key file data is corrupted or tampered
	ErrCodeKeyMismatch       = "KEY_MISMATCH"        // Provided key does not match the encryption

	// Encryption/Decryption errors - errors during cryptographic operations
	ErrCodeEncryptFailed    = "ENCRYPT_FAILED"      // Encryption operation failed
	ErrCodeDecryptFailed    = "DECRYPT_FAILED"      // Decryption operation failed
	ErrCodeInvalidVersion   = "INVALID_VERSION"     // Unsupported file format version
	ErrCodeInvalidCiphertext = "INVALID_CIPHERTEXT" // Ciphertext is invalid or corrupted
	ErrCodeInvalidNonce     = "INVALID_NONCE"       // Nonce is invalid or has wrong size

	// Input validation errors - errors from invalid user input or parameters
	ErrCodeInvalidInput     = "INVALID_INPUT"      // General invalid input error
	ErrCodeMissingInput     = "MISSING_INPUT"      // Required input parameter is missing
	ErrCodeInvalidEncoding  = "INVALID_ENCODING"   // Specified encoding is not supported
	ErrCodeInvalidParameter = "INVALID_PARAMETER"  // A parameter has an invalid value
)

// NewFileNotFoundError creates a NeptuneError for when a file cannot be found.
//
// Parameters:
//   - path:  The file path that could not be found.
//   - cause: The underlying error that caused the failure (may be nil).
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFileNotFound.
func NewFileNotFoundError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileNotFound,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewFileReadError creates a NeptuneError for when a file cannot be read.
//
// Parameters:
//   - path:  The path of the file that failed to read.
//   - cause: The underlying error that caused the read failure.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFileReadFailed.
func NewFileReadError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileReadFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewFileWriteError creates a NeptuneError for when a file cannot be written.
//
// Parameters:
//   - path:  The path of the file that failed to write.
//   - cause: The underlying error that caused the write failure.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFileWriteFailed.
func NewFileWriteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileWriteFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewFileCreateError creates a NeptuneError for when a file cannot be created.
//
// Parameters:
//   - path:  The path where the file could not be created.
//   - cause: The underlying error that caused the creation failure.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFileCreateFailed.
func NewFileCreateError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileCreateFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewFilePermissionError creates a NeptuneError for insufficient file permissions.
//
// Parameters:
//   - path:  The path of the file with permission issues.
//   - cause: The underlying error that indicates the permission problem.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFilePermission.
func NewFilePermissionError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFilePermission,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewFileTooLargeError creates a NeptuneError for when a file exceeds the
// maximum allowed size limit.
//
// Parameters:
//   - path:    The path of the file that is too large.
//   - size:    The actual size of the file in bytes.
//   - maxSize: The maximum allowed file size in bytes.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFileTooLarge.
func NewFileTooLargeError(path string, size, maxSize int64) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileTooLarge,
		Message: fmt.Sprintf(": %s (: %d , : %d )", path, size, maxSize),
		Suggestion: "",
	}
}

// NewFileEmptyError creates a NeptuneError for when a file is unexpectedly empty.
//
// Parameters:
//   - path: The path of the empty file.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFileEmpty.
func NewFileEmptyError(path string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileEmpty,
		Message: fmt.Sprintf(": %s", path),
		Suggestion: "",
	}
}

// NewFileDeleteError creates a NeptuneError for when a file cannot be deleted.
//
// Parameters:
//   - path:  The path of the file that failed to delete.
//   - cause: The underlying error that caused the deletion failure.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeFileWriteFailed (used for delete operations).
func NewFileDeleteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeFileWriteFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewInvalidPathError creates a NeptuneError for an invalid file path.
//
// Parameters:
//   - path:  The invalid path string.
//   - cause: The underlying error indicating why the path is invalid (may be nil).
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidPath.
func NewInvalidPathError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidPath,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyNotFoundError creates a NeptuneError for when an encryption key file
// cannot be found.
//
// Parameters:
//   - path:  The path where the key file was expected.
//   - cause: The underlying error indicating the key was not found (may be nil).
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyNotFound.
func NewKeyNotFoundError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyNotFound,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: " 'neptune keygen' ",
	}
}

// NewKeyReadError creates a NeptuneError for when a key file cannot be read.
//
// Parameters:
//   - path:  The path of the key file that failed to read.
//   - cause: The underlying error that caused the read failure.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyReadFailed.
func NewKeyReadError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyReadFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyWriteError creates a NeptuneError for when a key file cannot be written.
//
// Parameters:
//   - path:  The path where the key file should be written.
//   - cause: The underlying error that caused the write failure.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyWriteFailed.
func NewKeyWriteError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyWriteFailed,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyInvalidFormatError creates a NeptuneError for when a key file has
// an invalid or unrecognized format.
//
// Parameters:
//   - path:     The path of the key file with invalid format.
//   - encoding: The expected encoding format.
//   - cause:    The underlying error indicating the format issue (may be nil).
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyInvalidFormat.
func NewKeyInvalidFormatError(path, encoding string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyInvalidFormat,
		Message: fmt.Sprintf(": %s (: %s)", path, encoding),
		Cause:  cause,
		Suggestion: fmt.Sprintf(" (%s)", encoding),
	}
}

// NewKeyInvalidSizeError creates a NeptuneError for when a key has an
// incorrect size.
//
// Parameters:
//   - expectedSize: The expected key size in bytes.
//   - actualSize:   The actual size of the provided key in bytes.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyInvalidSize.
func NewKeyInvalidSizeError(expectedSize, actualSize int) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyInvalidSize,
		Message: fmt.Sprintf(":  %d ,  %d ", expectedSize, actualSize),
		Suggestion: "",
	}
}

// NewKeyCorruptedError creates a NeptuneError for when a key file's data
// is corrupted or has been tampered with.
//
// Parameters:
//   - path:  The path of the corrupted key file.
//   - cause: The underlying error indicating corruption (may be nil).
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyCorrupted.
func NewKeyCorruptedError(path string, cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyCorrupted,
		Message: fmt.Sprintf(": %s", path),
		Cause:  cause,
		Suggestion: "",
	}
}

// NewKeyMismatchError creates a NeptuneError for when the provided key
// does not match the key used for encryption.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyMismatch.
func NewKeyMismatchError() *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeKeyMismatch,
		Message: "",
		Suggestion: "",
	}
}

// NewEncryptError creates a NeptuneError for a general encryption failure.
//
// Parameters:
//   - cause: The underlying error that caused the encryption to fail.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeEncryptFailed.
func NewEncryptError(cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeEncryptFailed,
		Message: "",
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewDecryptError creates a NeptuneError for a general decryption failure.
//
// Parameters:
//   - cause: The underlying error that caused the decryption to fail.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeDecryptFailed.
func NewDecryptError(cause error) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeDecryptFailed,
		Message: "",
		Cause:  cause,
		Suggestion: "，",
	}
}

// NewInvalidVersionError creates a NeptuneError for when an encrypted file
// has an unsupported format version.
//
// Parameters:
//   - version: The version byte found in the file.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidVersion.
func NewInvalidVersionError(version byte) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidVersion,
		Message: fmt.Sprintf(": %d", version),
		Suggestion: " Neptune ",
	}
}

// NewInvalidCiphertextError creates a NeptuneError for invalid or corrupted
// ciphertext data.
//
// Parameters:
//   - reason: A description of why the ciphertext is considered invalid.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidCiphertext.
func NewInvalidCiphertextError(reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidCiphertext,
		Message: fmt.Sprintf(": %s", reason),
		Suggestion: "",
	}
}

// NewInvalidInputError creates a NeptuneError for invalid user input.
//
// Parameters:
//   - param:  The name of the parameter that is invalid.
//   - reason: A description of why the input is invalid.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidInput.
func NewInvalidInputError(param, reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidInput,
		Message: fmt.Sprintf(" '%s': %s", param, reason),
		Suggestion: "",
	}
}

// NewMissingInputError creates a NeptuneError for when a required input
// parameter is missing.
//
// Parameters:
//   - param: The name of the missing parameter.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeMissingInput.
func NewMissingInputError(param string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeMissingInput,
		Message: fmt.Sprintf(": %s", param),
		Suggestion: fmt.Sprintf(" --%s ", param),
	}
}

// NewInvalidEncodingError creates a NeptuneError for when a specified
// encoding format is not supported.
//
// Parameters:
//   - encoding:  The encoding that was requested but is not supported.
//   - supported: A list of supported encoding formats.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidEncoding.
func NewInvalidEncodingError(encoding string, supported []string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidEncoding,
		Message: fmt.Sprintf(": %s", encoding),
		Suggestion: fmt.Sprintf(": %v", supported),
	}
}

// NewInvalidParameterError creates a NeptuneError for when a parameter
// has an invalid value.
//
// Parameters:
//   - param:  The name of the parameter with the invalid value.
//   - value:  The invalid value that was provided.
//   - reason: An explanation of why the value is invalid.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewInvalidParameterError(param, value, reason string) *NeptuneError {
	return &NeptuneError{
		Code:   ErrCodeInvalidParameter,
		Message: fmt.Sprintf(" '%s'  '%s' : %s", param, value, reason),
		Suggestion: "",
	}
}

// IsNeptuneError checks whether an error is (or wraps) a NeptuneError.
// It uses errors.As to traverse the error chain.
//
// Parameters:
//   - err: The error to check.
//
// Returns:
//   - true if err is or wraps a NeptuneError, false otherwise.
func IsNeptuneError(err error) bool {
	var ne *NeptuneError
	return errors.As(err, &ne)
}

// GetNeptuneError extracts a NeptuneError from an error chain.
// If the error is not a NeptuneError and does not wrap one, it returns nil.
//
// Parameters:
//   - err: The error to extract from.
//
// Returns:
//   - A pointer to the NeptuneError if found, nil otherwise.
func GetNeptuneError(err error) *NeptuneError {
	var ne *NeptuneError
	if errors.As(err, &ne) {
		return ne
	}
	return nil
}

// WrapError wraps a standard error into a NeptuneError with additional
// context including an error code, message, and suggestion.
//
// Parameters:
//   - err:        The underlying error to wrap (may be nil).
//   - code:       The error code for the new NeptuneError.
//   - message:    The user-facing error message.
//   - suggestion: A suggested action to resolve the error (may be empty).
//
// Returns:
//   - A pointer to a new NeptuneError wrapping the provided error.
func WrapError(err error, code, message, suggestion string) *NeptuneError {
	return &NeptuneError{
		Code:       code,
		Message:    message,
		Cause:      err,
		Suggestion: suggestion,
	}
}

// NewDecryptKeyMismatchError creates a NeptuneError specifically for
// decryption failures caused by a key mismatch (wrong key used).
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeKeyMismatch.
func NewDecryptKeyMismatchError() *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeKeyMismatch,
		Message:    "：",
		Suggestion: "，",
	}
}

// NewHashMismatchError creates a NeptuneError for when a hash verification
// fails, indicating data corruption or tampering.
//
// Parameters:
//   - expected: The expected hash value.
//   - actual:   The actual computed hash value.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidCiphertext.
func NewHashMismatchError(expected, actual string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidCiphertext,
		Message:    fmt.Sprintf(":  %s,  %s", expected, actual),
		Suggestion: "",
	}
}

// NewNotEnoughMemoryError creates a NeptuneError for when there is
// insufficient memory to perform an operation.
//
// Parameters:
//   - size: The amount of memory (in bytes) that was requested.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewNotEnoughMemoryError(size int64) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf("： %d ", size),
		Suggestion: "",
	}
}

// NewInvalidStateError creates a NeptuneError for when the system is in
// an invalid or unexpected state.
//
// Parameters:
//   - message: A description of the invalid state.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewInvalidStateError(message string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", message),
		Suggestion: "",
	}
}

// NewOperationNotSupportedError creates a NeptuneError for when an
// operation is not supported on the current platform or configuration.
//
// Parameters:
//   - operation: The name of the unsupported operation.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewOperationNotSupportedError(operation string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", operation),
		Suggestion: "",
	}
}

// NewConversionError creates a NeptuneError for when a data type
// conversion fails.
//
// Parameters:
//   - from: The source type being converted from.
//   - to:   The target type being converted to.
//   - err:  The underlying error that caused the conversion to fail.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewConversionError(from, to string, err error) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s -> %s", from, to),
		Cause:      err,
		Suggestion: "",
	}
}

// NewDependencyError creates a NeptuneError for when an external
// dependency or service is unavailable or fails.
//
// Parameters:
//   - dep: The name of the dependency that failed.
//   - err: The underlying error from the dependency.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewDependencyError(dep string, err error) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", dep),
		Cause:      err,
		Suggestion: "",
	}
}

// NewTimeoutError creates a NeptuneError for when an operation times out.
//
// Parameters:
//   - operation: The name of the operation that timed out.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewTimeoutError(operation string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", operation),
		Suggestion: "",
	}
}

// NewResourceExhaustedError creates a NeptuneError for when a system
// resource has been exhausted (e.g., file handles, memory, connections).
//
// Parameters:
//   - resource: The name of the exhausted resource.
//
// Returns:
//   - A pointer to a NeptuneError with code ErrCodeInvalidParameter.
func NewResourceExhaustedError(resource string) *NeptuneError {
	return &NeptuneError{
		Code:       ErrCodeInvalidParameter,
		Message:    fmt.Sprintf(": %s", resource),
		Suggestion: "",
	}
}

// PrintErrorWithCode prints the error to standard output with its error code,
// underlying cause (if present), and suggested action (if present).
// The output uses a formatted style with an error icon and indentation.
func (e *NeptuneError) PrintErrorWithCode() {
	fmt.Printf("\n✗ [%s] %s\n", e.Code, e.Message)
	if e.Cause != nil {
		fmt.Printf("  : %v\n", e.Cause)
	}
	if e.Suggestion != "" {
		fmt.Printf("  : %s\n", e.Suggestion)
	}
}

// PrintDetailed prints a detailed error report to standard output.
// Currently a placeholder with no implementation.
func (e *NeptuneError) PrintDetailed() {
}

// IsErrorType checks whether an error is a NeptuneError with a specific
// error code. It traverses the error chain using errors.As.
//
// Parameters:
//   - err:  The error to check.
//   - code: The error code to match against.
//
// Returns:
//   - true if err is or wraps a NeptuneError with the given code, false otherwise.
func IsErrorType(err error, code string) bool {
	var ne *NeptuneError
	if errors.As(err, &ne) {
		return ne.Code == code
	}
	return false
}

// GetErrorCode extracts the error code from an error if it is a NeptuneError.
// If the error is not a NeptuneError, it returns an empty string.
//
// Parameters:
//   - err: The error to extract the code from.
//
// Returns:
//   - The error code string if err is a NeptuneError, empty string otherwise.
func GetErrorCode(err error) string {
	var ne *NeptuneError
	if errors.As(err, &ne) {
		return ne.Code
	}
	return ""
}

// FormatErrorList formats a slice of errors into a single human-readable
// string with numbered items. Each error is displayed with its index.
// NeptuneErrors include their error code in the output.
//
// Parameters:
//   - errs: A slice of errors to format.
//
// Returns:
//   - A multi-line string with each error numbered and formatted.
func FormatErrorList(errs []error) string {
	var messages []string
	// Iterate through each error and format it appropriately
	for i, err := range errs {
		// Check if it's a NeptuneError to include the error code
		if ne := GetNeptuneError(err); ne != nil {
			messages = append(messages, fmt.Sprintf("%d. [%s] %s", i+1, ne.Code, ne.Message))
		} else {
			// Standard error - just use the error message
			messages = append(messages, fmt.Sprintf("%d. %v", i+1, err))
		}
	}
	return strings.Join(messages, "\n")
}

// AggregateErrors combines multiple errors into a single NeptuneError.
// If the slice is empty, it returns nil. If there is exactly one error,
// it returns that error unchanged. Otherwise, it aggregates all error
// messages into a single NeptuneError with code ErrCodeInvalidInput.
//
// Parameters:
//   - errs: A slice of errors to aggregate.
//
// Returns:
//   - nil if no errors, the single error if one, or an aggregated NeptuneError if multiple.
func AggregateErrors(errs []error) error {
	// No errors - return nil
	if len(errs) == 0 {
		return nil
	}
	// Single error - return it directly
	if len(errs) == 1 {
		return errs[0]
	}

	// Multiple errors - collect all messages and aggregate
	var messages []string
	for _, err := range errs {
		messages = append(messages, err.Error())
	}

	return &NeptuneError{
		Code:    ErrCodeInvalidInput,
		Message: fmt.Sprintf(":\n%s", strings.Join(messages, "\n")),
	}
}

// HandleError is a convenience function for handling errors in CLI contexts.
// If the error is a NeptuneError, it prints the detailed error report.
// Otherwise, it prints a generic error message to stderr.
// If err is nil, this function does nothing.
//
// Parameters:
//   - err: The error to handle (nil is a no-op).
func HandleError(err error) {
	// No error - nothing to handle
	if err == nil {
		return
	}

	// NeptuneError - use detailed printing
	if ne := GetNeptuneError(err); ne != nil {
		ne.PrintDetailed()
	} else {
		// Standard error - print to stderr with basic formatting
		fmt.Fprintf(os.Stderr, "\n✗ : %v\n", err)
	}
}

// Must is a helper that panics if an error is not nil.
// It is intended for use in situations where an error should never occur
// and program termination is the only reasonable response.
// If the error is a NeptuneError, the panic message includes FullError().
//
// Parameters:
//   - err: The error to check. If nil, the function returns normally.
func Must(err error) {
	if err != nil {
		if ne := GetNeptuneError(err); ne != nil {
			panic(ne.FullError())
		}
		panic(err)
	}
}

// IgnoreError is a no-op function that explicitly ignores an error.
// It is useful for documenting intentional error suppression for
// optional operations where failure is acceptable.
//
// Parameters:
//   - err: The error to ignore.
func IgnoreError(err error) {}

// SuppressError suppresses specific error types by their error code.
// If the error matches any of the provided codes, it returns nil.
// Otherwise, it returns the original error unchanged.
// If err is nil, it returns nil.
//
// Parameters:
//   - err:   The error to potentially suppress.
//   - codes: Variadic list of error codes to suppress.
//
// Returns:
//   - nil if err matches any of the codes or is nil, otherwise the original err.
func SuppressError(err error, codes ...string) error {
	if err == nil {
		return nil
	}

	// Check if it's a NeptuneError with a code that should be suppressed
	if ne := GetNeptuneError(err); ne != nil {
		for _, code := range codes {
			if ne.Code == code {
				return nil
			}
		}
	}

	return err
}
