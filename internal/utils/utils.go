// Package utils provides a comprehensive set of utility functions for the Neptune
// encryption tool. It includes file operations, key management, validation helpers,
// string utilities, encoding/decoding, HTTP download capabilities, and buffer pooling.
// These utilities are designed to support the core encryption and decryption workflows
// with robust error handling and cross-platform compatibility.
package utils

import (
	"bufio"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Core configuration constants for the Neptune encryption system.
// These values define the boundaries and expected formats for encryption operations.
const (
	// MaxFileSize is the maximum allowed file size for encryption operations,
	// set to 100 megabytes. This constant is retained for historical reference
	// as streaming encryption now supports files of any size.
	MaxFileSize int64 = 100 * 1024 * 1024

	// KeySize is the expected size in bytes for Curve25519 elliptic curve keys.
	// Both public and private keys must be exactly 32 bytes long.
	KeySize = 32

	// MinKeyFileSize is the minimum acceptable file size for a key file in bytes.
	// A valid key file must contain at least 32 bytes of hex-encoded key material.
	MinKeyFileSize int64 = 32

	// NeptuneFileExtension is the standard file extension used for files that
	// have been encrypted with Neptune. Files with this extension are treated
	// as encrypted ciphertext.
	NeptuneFileExtension = ".ntp"

	// NeptuneMinHeaderSize is the minimum number of bytes required for a valid
	// Neptune encrypted file header. The header consists of:
	//   - 1 byte: version identifier
	//   - 32 bytes: ephemeral public key
	//   - 16 bytes: nonce for symmetric encryption
	NeptuneMinHeaderSize = 49
)

// EncodingType defines the supported encoding formats for cryptographic keys.
// It enumerates the serialization formats used when storing or transmitting
// key material as human-readable strings.
type EncodingType int

// Supported key encoding format constants.
// These represent the available serialization schemes for key data.
const (
	// EncodingHex represents hexadecimal encoding, where each byte is
	// represented by two hexadecimal characters (0-9, a-f).
	EncodingHex EncodingType = iota

	// EncodingBase64 represents standard Base64 encoding as defined in
	// RFC 4648, using the standard alphabet with '+' and '/' characters.
	EncodingBase64

	// EncodingBase64URL represents URL-safe Base64 encoding as defined in
	// RFC 4648, using '-' and '_' characters instead of '+' and '/'.
	EncodingBase64URL
)

// ParseEncodingType converts a string representation of an encoding format
// into the corresponding EncodingType value. The comparison is case-insensitive.
//
// Parameters:
//   - s: A string representing the encoding format ("hex", "base64", or "base64url").
//
// Returns:
//   - EncodingType: The corresponding encoding type constant on success.
//   - error: An InvalidEncodingError if the string does not match a supported format.
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

// String returns the lowercase string representation of the EncodingType.
// This implements the fmt.Stringer interface for convenient string formatting.
//
// Returns:
//   - string: The encoding format as a lowercase string ("hex", "base64", "base64url"),
//     or "unknown" if the encoding type is not recognized.
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

// FileExists checks whether a file exists at the given path and is accessible
// as a regular file (not a directory). It performs a stat operation and
// classifies any errors with Neptune-specific error types.
//
// Parameters:
//   - path: The filesystem path to check.
//
// Returns:
//   - error: nil if the file exists and is a regular file; otherwise a
//     NeptuneError with an appropriate error code (FileNotFound,
//     FilePermission, FileRead, or InvalidPath).
func FileExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		// Distinguish between common error types to provide specific feedback
		if os.IsNotExist(err) {
			return NewFileNotFoundError(path, err)
		}
		if os.IsPermission(err) {
			return NewFilePermissionError(path, err)
		}
		return NewFileReadError(path, err)
	}

	// Verify the path refers to a file, not a directory
	if info.IsDir() {
		return NewInvalidPathError(path, fmt.Errorf("path is a directory"))
	}

	return nil
}

// ValidateFileForRead performs comprehensive validation of a file before
// reading operations. It checks existence, accessibility, and that the file
// is non-empty.
//
// Parameters:
//   - path: The filesystem path of the file to validate.
//
// Returns:
//   - error: nil if the file is valid for reading; otherwise a NeptuneError
//     describing the validation failure.
func ValidateFileForRead(path string) error {
	// Phase 1: Verify the file exists and is accessible
	if err := FileExists(path); err != nil {
		return err
	}

	// Phase 2: Validate file size is non-zero
	info, err := os.Stat(path)
	if err != nil {
		return NewFileReadError(path, err)
	}

	if info.Size() == 0 {
		return NewFileEmptyError(path)
	}

	// Note: File size limit was removed as streaming encryption can handle
	// files of any size. The original limit check is preserved as comments
	// for historical reference.
	// if info.Size() > MaxFileSize {
	// 	return NewFileTooLargeError(path, info.Size(), MaxFileSize)
	// }

	return nil
}

// ValidateFileForWrite validates that a target path is suitable for writing
// a file. It checks path validity, handles overwrite semantics, and verifies
// the parent directory exists and is a valid directory.
//
// Parameters:
//   - path: The target filesystem path for the output file.
//   - overwrite: If true, allows overwriting an existing file at the path.
//     If false, returns an error if the file already exists.
//
// Returns:
//   - error: nil if the path is valid for writing; otherwise a NeptuneError
//     describing the validation failure with a suggested remedy.
func ValidateFileForWrite(path string, overwrite bool) error {
	// Resolve to absolute path for consistent validation
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	// Check if a file already exists at the target path
	info, err := os.Stat(absPath)
	if err == nil {
		// File exists - respect overwrite flag
		if !overwrite {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("file already exists: %s", path),
				Suggestion: "use --force flag to overwrite or specify a different output path",
			}
		}
		// Ensure existing path is not a directory
		if info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("path is a directory"))
		}
	}

	// Verify the parent directory exists and is valid
	parentDir := filepath.Dir(absPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("directory does not exist: %s", parentDir),
				Suggestion: "create the directory first or specify a valid output path",
			}
		}
		return NewFileWriteError(path, err)
	}

	if !parentInfo.IsDir() {
		return NewInvalidPathError(parentDir, fmt.Errorf("parent path is not a directory"))
	}

	return nil
}

// ValidateKeyFile validates that a key file exists, is non-empty, and contains
// a properly formatted cryptographic key that can be decoded using the specified
// encoding. Only the first line of the file is validated as the key material.
//
// Parameters:
//   - path: The filesystem path to the key file.
//   - encoding: The expected encoding format of the key (hex, base64, or base64url).
//
// Returns:
//   - error: nil if the key file is valid; otherwise a NeptuneError describing
//     the validation failure (file not found, empty file, invalid format, etc.).
func ValidateKeyFile(path string, encoding EncodingType) error {
	// Step 1: Verify the file exists and is accessible
	if err := FileExists(path); err != nil {
		return err
	}

	// Step 2: Read the entire file content into memory
	content, err := os.ReadFile(path)
	if err != nil {
		return NewKeyReadError(path, err)
	}

	// Step 3: Basic sanity check - file must not be empty
	if len(content) == 0 {
		return NewKeyCorruptedError(path, fmt.Errorf("file is empty"))
	}

	// Step 4: Split content into lines and validate format
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 {
		return NewKeyCorruptedError(path, fmt.Errorf("invalid file format"))
	}

	// Step 5: Extract and validate the first line as the key string
	keyStr := strings.TrimSpace(lines[0])
	if keyStr == "" {
		return NewKeyCorruptedError(path, fmt.Errorf("key content is empty"))
	}

	// Step 6: Attempt to decode the key to verify it is properly formatted
	_, err = DecodeKey(keyStr, encoding)
	if err != nil {
		return NewKeyInvalidFormatError(path, encoding.String(), err)
	}

	return nil
}

// DecodeKey decodes a key string from its serialized text format into raw bytes
// using the specified encoding. It also validates that the resulting key has
// the correct length (KeySize bytes for Curve25519).
//
// Parameters:
//   - keyStr: The encoded key string to decode.
//   - encoding: The encoding format used for the key string.
//
// Returns:
//   - []byte: The decoded raw key bytes on success.
//   - error: An error if decoding fails or the resulting key has an invalid size.
func DecodeKey(keyStr string, encoding EncodingType) ([]byte, error) {
	var decoded []byte
	var err error

	// Select the appropriate decoding algorithm based on encoding type
	switch encoding {
	case EncodingHex:
		decoded, err = hex.DecodeString(keyStr)
	case EncodingBase64:
		decoded, err = base64.StdEncoding.DecodeString(keyStr)
	case EncodingBase64URL:
		decoded, err = base64.URLEncoding.DecodeString(keyStr)
	default:
		// Fallback to hex for unknown encoding types
		decoded, err = hex.DecodeString(keyStr)
	}

	if err != nil {
		return nil, fmt.Errorf("decoding failed: %w", err)
	}

	// Validate decoded key matches expected Curve25519 key size
	if len(decoded) != KeySize {
		return nil, NewKeyInvalidSizeError(KeySize, len(decoded))
	}

	return decoded, nil
}

// EncodeKey encodes raw key bytes into a string representation using the
// specified encoding format. This is the inverse operation of DecodeKey.
//
// Parameters:
//   - key: The raw key bytes to encode.
//   - encoding: The encoding format to use for serialization.
//
// Returns:
//   - string: The encoded key string. Falls back to hex if the encoding type
//     is unrecognized.
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

// ReadFileContent reads the entire content of a file after validating that
// the file exists, is accessible, and is non-empty.
//
// Parameters:
//   - path: The filesystem path of the file to read.
//
// Returns:
//   - []byte: The file content as a byte slice on success.
//   - error: A NeptuneError if validation fails or the file cannot be read.
func ReadFileContent(path string) ([]byte, error) {
	// Validate file suitability before attempting to read
	if err := ValidateFileForRead(path); err != nil {
		return nil, err
	}

	// Read the entire file into memory
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, NewFileReadError(path, err)
	}

	return content, nil
}

// WriteFileContent writes binary data to a file after validating the output
// path. The file is created with 0644 permissions (owner read/write, group
// read, others read).
//
// Parameters:
//   - path: The target filesystem path for the output file.
//   - content: The binary data to write to the file.
//   - overwrite: If true, allows overwriting an existing file. If false,
//     returns an error if the file already exists.
//
// Returns:
//   - error: nil if the write succeeds; otherwise a NeptuneError describing
//     the validation or write failure.
func WriteFileContent(path string, content []byte, overwrite bool) error {
	// Validate the target path is suitable for writing
	if err := ValidateFileForWrite(path, overwrite); err != nil {
		return err
	}

	// Write content to file with standard file permissions
	err := os.WriteFile(path, content, 0644)
	if err != nil {
		return NewFileWriteError(path, err)
	}

	return nil
}

// EnsureDirectory verifies that a directory exists at the given path. If the
// directory does not exist, it is created recursively with 0755 permissions.
// If the path exists but is a file rather than a directory, an error is returned.
//
// Parameters:
//   - path: The filesystem path of the directory to ensure.
//
// Returns:
//   - error: nil if the directory exists or was created successfully; otherwise
//     a NeptuneError describing the failure.
func EnsureDirectory(path string) error {
	// Resolve to absolute path for consistent handling
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	// Check if path already exists
	info, err := os.Stat(absPath)
	if err == nil {
		// Path exists - verify it's a directory, not a file
		if !info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("path is a file, not a directory"))
		}
		return nil
	}

	// Path does not exist - create it recursively
	if os.IsNotExist(err) {
		if err := os.MkdirAll(absPath, 0755); err != nil {
			return NewFileCreateError(path, err)
		}
		return nil
	}

	// Other stat error (e.g., permission denied)
	return NewFileCreateError(path, err)
}

// ValidateInputParameters enforces that exactly one input source is provided:
// either a file path or inline text, but not both and not neither.
//
// Parameters:
//   - inputFile: Path to an input file, or empty string if not provided.
//   - text: Inline text input, or empty string if not provided.
//
// Returns:
//   - error: nil if exactly one input source is provided; otherwise a
//     MissingInputError or InvalidInputError.
func ValidateInputParameters(inputFile, text string) error {
	// Both inputs missing - invalid
	if inputFile == "" && text == "" {
		return NewMissingInputError("input")
	}
	// Both inputs provided - mutually exclusive
	if inputFile != "" && text != "" {
		return NewInvalidInputError("input", "cannot specify both --input and --text")
	}
	return nil
}

// ValidateKeyParameters validates the provided key files (public and/or private)
// using the specified encoding format. Each key file is validated independently
// only if its path is non-empty.
//
// Parameters:
//   - publicKeyFile: Path to the public key file, or empty string to skip.
//   - privateKeyFile: Path to the private key file, or empty string to skip.
//   - encoding: The expected encoding format for both key files.
//
// Returns:
//   - error: nil if all provided key files are valid; otherwise the first
//     validation error encountered.
func ValidateKeyParameters(publicKeyFile, privateKeyFile string, encoding EncodingType) error {
	// Validate public key file if one was provided
	if publicKeyFile != "" {
		if err := ValidateKeyFile(publicKeyFile, encoding); err != nil {
			return err
		}
	}

	// Validate private key file if one was provided
	if privateKeyFile != "" {
		if err := ValidateKeyFile(privateKeyFile, encoding); err != nil {
			return err
		}
	}

	return nil
}

// FormatFileSize converts a raw byte count into a human-readable string with
// appropriate units (B, KB, MB, or GB). Values are formatted to two decimal
// places for KB, MB, and GB.
//
// Parameters:
//   - bytes: The file size in bytes as an int64.
//
// Returns:
//   - string: A formatted string representing the file size (e.g., "1.50 MB").
func FormatFileSize(bytes int64) string {
	// Binary (base-1024) unit definitions for file sizing
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	// Select the most appropriate unit for readability
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

// GetFileInfo retrieves basic information about a file and formats it as a
// human-readable string containing the path and file size.
//
// Parameters:
//   - path: The filesystem path of the file to inspect.
//
// Returns:
//   - string: A formatted string like "path/to/file.txt (1.50 MB)".
//   - error: A NeptuneError if the file cannot be stat'd.
func GetFileInfo(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", NewFileReadError(path, err)
	}

	return fmt.Sprintf("%s (%s)", path, FormatFileSize(info.Size())), nil
}

// PrintSuccess outputs a success message to stdout prefixed with [SUCCESS].
// Accepts a format string and optional arguments in the style of fmt.Printf.
//
// Parameters:
//   - format: A printf-style format string for the success message.
//   - args: Optional arguments to substitute into the format string.
func PrintSuccess(format string, args ...interface{}) {
	fmt.Printf("[SUCCESS] %s\n", fmt.Sprintf(format, args...))
}

// PrintError outputs an error message to stderr prefixed with [ERROR].
// Accepts a format string and optional arguments in the style of fmt.Printf.
//
// Parameters:
//   - format: A printf-style format string for the error message.
//   - args: Optional arguments to substitute into the format string.
func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", fmt.Sprintf(format, args...))
}

// PrintWarning outputs a warning message to stdout prefixed with [WARNING].
// Accepts a format string and optional arguments in the style of fmt.Printf.
//
// Parameters:
//   - format: A printf-style format string for the warning message.
//   - args: Optional arguments to substitute into the format string.
func PrintWarning(format string, args ...interface{}) {
	fmt.Printf("[WARNING] %s\n", fmt.Sprintf(format, args...))
}

// PrintInfo outputs an informational message to stdout prefixed with [INFO].
// Accepts a format string and optional arguments in the style of fmt.Printf.
//
// Parameters:
//   - format: A printf-style format string for the info message.
//   - args: Optional arguments to substitute into the format string.
func PrintInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] %s\n", fmt.Sprintf(format, args...))
}

// PrintQuestion outputs a question prompt to stdout prefixed with [QUESTION].
// Unlike other print functions, the trailing newline is omitted so that user
// input can be entered on the same line.
//
// Parameters:
//   - format: A printf-style format string for the question prompt.
//   - args: Optional arguments to substitute into the format string.
func PrintQuestion(format string, args ...interface{}) {
	fmt.Printf("[QUESTION] %s ", fmt.Sprintf(format, args...))
}

// CopyFile copies a file from the source path to the destination path using
// streaming I/O. Both source and destination are validated before the copy
// operation begins. The copy uses io.Copy for efficient streaming.
//
// Parameters:
//   - src: The filesystem path of the source file to copy.
//   - dst: The target filesystem path for the copied file.
//   - overwrite: If true, allows overwriting an existing file at dst.
//
// Returns:
//   - error: nil if the copy succeeds; otherwise a NeptuneError describing
//     the validation or copy failure.
func CopyFile(src, dst string, overwrite bool) error {
	// Validate source file is readable
	if err := ValidateFileForRead(src); err != nil {
		return err
	}
	// Validate destination path is writable
	if err := ValidateFileForWrite(dst, overwrite); err != nil {
		return err
	}

	// Open source file for reading
	srcFile, err := os.Open(src)
	if err != nil {
		return NewFileReadError(src, err)
	}
	defer srcFile.Close()

	// Create or truncate destination file
	dstFile, err := os.Create(dst)
	if err != nil {
		return NewFileWriteError(dst, err)
	}
	defer dstFile.Close()

	// Stream data from source to destination efficiently
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return NewFileWriteError(dst, err)
	}

	return nil
}

// FileExistsCheck performs a simple boolean check for file existence.
// Unlike FileExists, it returns a boolean rather than detailed error types,
// making it convenient for quick existence checks where error details are not needed.
//
// Parameters:
//   - path: The filesystem path to check.
//
// Returns:
//   - bool: true if the path exists (file or directory), false if it does not.
func FileExistsCheck(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetFileSize retrieves the size of a file in bytes. It validates that the
// path exists, is accessible, and refers to a regular file (not a directory).
//
// Parameters:
//   - path: The filesystem path of the file.
//
// Returns:
//   - int64: The file size in bytes on success.
//   - error: A NeptuneError if the file cannot be accessed or is a directory.
func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, NewFileNotFoundError(path, err)
		}
		return 0, NewFileReadError(path, err)
	}
	// Reject directories since they don't have a meaningful file size
	if info.IsDir() {
		return 0, NewInvalidPathError(path, fmt.Errorf("path is a directory"))
	}
	return info.Size(), nil
}

// GetDirectories retrieves a list of all top-level subdirectories within a
// given directory path. Permission errors are handled gracefully by logging
// a warning and returning an empty slice.
//
// Parameters:
//   - dirPath: The filesystem path of the directory to scan.
//
// Returns:
//   - []string: A slice of absolute/relative paths to subdirectories.
//   - error: An error if the directory cannot be read (except permission errors).
func GetDirectories(dirPath string) ([]string, error) {
	var dirs []string
	files, err := os.ReadDir(dirPath)
	if err != nil {
		// Handle permission errors gracefully - warn and continue
		if os.IsPermission(err) {
			PrintWarning("Permission denied: %s", dirPath)
			return []string{}, nil
		}
		return nil, err
	}

	// Filter entries to only include directories
	for _, file := range files {
		if file.IsDir() {
			dirPath := filepath.Join(dirPath, file.Name())
			dirs = append(dirs, dirPath)
		}
	}
	return dirs, nil
}

// DeleteFile removes a file or directory using OS-specific system commands.
// On Windows it uses `cmd /c del /f /q`, and on Unix-like systems it uses
// `rm -rf`. This approach ensures robust deletion of read-only files and
// handles various edge cases better than os.Remove alone.
//
// Parameters:
//   - filePath: The filesystem path of the file or directory to delete.
//
// Returns:
//   - error: nil if deletion succeeds; an error if the path is empty or
//     the delete command fails.
func DeleteFile(filePath string) error {
	// Guard against empty path
	if filePath == "" {
		return fmt.Errorf("file path is empty")
	}

	// Select the appropriate delete command based on operating system
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "del", "/f", "/q", filePath)
	default:
		cmd = exec.Command("rm", "-rf", filePath)
	}

	// Execute the delete command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}

	return nil
}

// RemoveSourceFileWithRetry attempts to delete a file with a retry mechanism
// to handle transient issues such as file locks or temporary unavailability.
// It retries up to maxRetries times with a fixed delay between attempts.
//
// Parameters:
//   - filePath: The filesystem path of the file to remove.
//
// Returns:
//   - error: nil if the file is successfully deleted within the retry limit;
//     otherwise an error describing the final failure.
func RemoveSourceFileWithRetry(filePath string) error {
	const maxRetries = 3
	const retryDelay = 1000

	// Attempt deletion with retries on failure
	for i := 0; i < maxRetries; i++ {
		if err := DeleteFile(filePath); err == nil {
			return nil
		}

		// Wait before retrying (skip delay on last attempt)
		if i < maxRetries-1 {
			time.Sleep(time.Duration(retryDelay) * time.Millisecond)
		}
	}

	return fmt.Errorf("failed to remove file after %d retries", maxRetries)
}

// ShuffleStrings randomizes the order of elements in a string slice using the
// Fisher-Yates (Knuth) shuffle algorithm. The shuffle is performed in-place,
// modifying the original slice.
//
// Parameters:
//   - slice: The slice of strings to shuffle. It is modified in place.
func ShuffleStrings(slice []string) {
	// Fisher-Yates algorithm: iterate from end to start, swapping each element
	// with a randomly selected element from the unshuffled portion
	for i := len(slice) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// ComputeFileHash calculates the SHA-256 cryptographic hash of a file's contents.
// The file is streamed through the hash function using io.Copy to handle large
// files efficiently without loading them entirely into memory.
//
// Parameters:
//   - path: The filesystem path of the file to hash.
//
// Returns:
//   - string: The hex-encoded SHA-256 hash of the file contents.
//   - error: A NeptuneError if the file cannot be read or validated.
func ComputeFileHash(path string) (string, error) {
	// Validate file before attempting to read
	if err := ValidateFileForRead(path); err != nil {
		return "", err
	}

	// Open file for streaming
	file, err := os.Open(path)
	if err != nil {
		return "", NewFileReadError(path, err)
	}
	defer file.Close()

	// Stream file content through SHA-256 hash function
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", NewFileReadError(path, err)
	}

	// Return hash as a lowercase hexadecimal string
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ReadLines reads a text file line by line and returns all lines as a slice
// of strings. It uses a bufio.Scanner for efficient line-by-line reading and
// validates the file before opening.
//
// Parameters:
//   - path: The filesystem path of the file to read.
//
// Returns:
//   - []string: A slice containing each line of the file (without newline characters).
//   - error: A NeptuneError if the file cannot be read or validated.
func ReadLines(path string) ([]string, error) {
	// Validate file suitability before opening
	if err := ValidateFileForRead(path); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, NewFileReadError(path, err)
	}
	defer file.Close()

	// Read file line by line using a scanner
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Check for scanner errors (e.g., read failure, buffer exceeded)
	if err := scanner.Err(); err != nil {
		return nil, NewFileReadError(path, err)
	}

	return lines, nil
}

// WriteLines writes a slice of strings to a file, one per line. Each line is
// terminated with a newline character. The output file is validated before
// writing and a buffered writer is used for efficiency.
//
// Parameters:
//   - path: The target filesystem path for the output file.
//   - lines: A slice of strings to write as individual lines.
//   - overwrite: If true, allows overwriting an existing file.
//
// Returns:
//   - error: nil if the write succeeds; otherwise a NeptuneError describing
//     the validation or write failure.
func WriteLines(path string, lines []string, overwrite bool) error {
	// Validate target path before creating file
	if err := ValidateFileForWrite(path, overwrite); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return NewFileWriteError(path, err)
	}
	defer file.Close()

	// Use buffered writer for efficient line-by-line output
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return NewFileWriteError(path, err)
		}
	}

	// Flush the buffer to ensure all data is written to disk
	if err := writer.Flush(); err != nil {
		return NewFileWriteError(path, err)
	}

	return nil
}

// CreateBackup creates a backup copy of a file by appending the ".bak" extension
// to the original file path. The backup always overwrites any existing .bak file.
//
// Parameters:
//   - path: The filesystem path of the file to back up.
//
// Returns:
//   - string: The filesystem path of the created backup file.
//   - error: A NeptuneError if the backup cannot be created.
func CreateBackup(path string) (string, error) {
	// Validate source file is readable before copying
	if err := ValidateFileForRead(path); err != nil {
		return "", err
	}

	// Construct backup path by appending .bak extension
	backupPath := path + ".bak"
	if err := CopyFile(path, backupPath, true); err != nil {
		return "", NewFileCreateError(backupPath, err)
	}

	return backupPath, nil
}

// ValidateDirectory verifies that a path refers to an existing directory.
// Optionally, it can create the directory (and any missing parents) if it
// does not already exist.
//
// Parameters:
//   - path: The filesystem path of the directory to validate.
//   - createIfNotExists: If true, creates the directory tree if it doesn't exist.
//     If false, returns an error if the directory does not exist.
//
// Returns:
//   - error: nil if the directory exists (or was created); otherwise a
//     NeptuneError describing the failure.
func ValidateDirectory(path string, createIfNotExists bool) error {
	// Resolve to absolute path for consistent handling
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	// Check if path already exists
	info, err := os.Stat(absPath)
	if err == nil {
		// Path exists - verify it's a directory
		if !info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("path is a file, not a directory"))
		}
		return nil
	}

	// Path does not exist
	if os.IsNotExist(err) {
		if !createIfNotExists {
			return NewFileNotFoundError(path, err)
		}
		// Create directory and any missing parent directories
		if err := os.MkdirAll(absPath, 0755); err != nil {
			return NewFileCreateError(path, err)
		}
		return nil
	}

	// Other stat error (e.g., permission issues)
	return NewFileReadError(path, err)
}

// SanitizeFileName removes characters that are invalid in file names across
// common operating systems (Windows, macOS, Linux). Each invalid character
// is replaced with an underscore.
//
// Parameters:
//   - name: The original file name string to sanitize.
//
// Returns:
//   - string: The sanitized file name with invalid characters replaced by underscores.
func SanitizeFileName(name string) string {
	// Characters that are not allowed in file names on Windows (and are
	// generally problematic on other platforms too)
	invalidChars := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range invalidChars {
		name = strings.ReplaceAll(name, char, "_")
	}
	return name
}

// GetRelativePath computes the relative path from a base directory to a target
// path. Both paths are resolved to absolute paths before computing the relative
// relationship.
//
// Parameters:
//   - base: The base directory path from which to compute the relative path.
//   - target: The target file or directory path.
//
// Returns:
//   - string: The relative path from base to target.
//   - error: A NeptuneError if either path cannot be resolved to absolute form.
func GetRelativePath(base, target string) (string, error) {
	// Resolve both paths to absolute form for consistent comparison
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

// ValidateFilePath performs comprehensive validation of a file path for reading.
// It checks that the path is not empty, resolves to an absolute path, exists,
// is accessible, and refers to a regular file (not a directory).
//
// Parameters:
//   - path: The filesystem path to validate.
//
// Returns:
//   - error: nil if the path is a valid, readable file; otherwise a NeptuneError.
func ValidateFilePath(path string) error {
	// Basic non-empty check
	if path == "" {
		return NewInvalidPathError(path, fmt.Errorf("path is empty"))
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	// Stat the file to check existence and type
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

	// Verify it's a file, not a directory
	if info.IsDir() {
		return NewInvalidPathError(path, fmt.Errorf("path is a directory"))
	}

	return nil
}

// ValidateOutputPath validates that an output file path is suitable for writing.
// It checks that the path is not empty, is not a directory, respects the
// overwrite flag, and that the parent directory exists.
//
// Parameters:
//   - path: The target output filesystem path to validate.
//   - overwrite: If true, allows overwriting an existing file at the path.
//
// Returns:
//   - error: nil if the output path is valid; otherwise a NeptuneError with
//     a suggested remedy.
func ValidateOutputPath(path string, overwrite bool) error {
	// Basic non-empty check
	if path == "" {
		return NewInvalidPathError(path, fmt.Errorf("output path is empty"))
	}

	// Resolve to absolute path for consistent validation
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	// Check if a file/directory already exists at the target path
	info, err := os.Stat(absPath)
	if err == nil {
		// Path exists - verify it's a file, not a directory
		if info.IsDir() {
			return NewInvalidPathError(path, fmt.Errorf("path is a directory"))
		}
		// Check overwrite policy
		if !overwrite {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("file already exists: %s", path),
				Suggestion: "use --force flag to overwrite or specify a different output path",
			}
		}
	}

	// Verify the parent directory exists and is valid
	parentDir := filepath.Dir(absPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &NeptuneError{
				Code:       ErrCodeFileWriteFailed,
				Message:    fmt.Sprintf("directory does not exist: %s", parentDir),
				Suggestion: "create the directory first or specify a valid output path",
			}
		}
		return NewFileWriteError(path, err)
	}

	if !parentInfo.IsDir() {
		return NewInvalidPathError(parentDir, fmt.Errorf("parent path is not a directory"))
	}

	return nil
}

// ValidateKeyData validates that raw key data has the correct size for
// Curve25519 keys (exactly 32 bytes). It checks for both empty data and
// incorrect length.
//
// Parameters:
//   - key: The raw key bytes to validate.
//
// Returns:
//   - error: nil if the key data has the correct size; otherwise a
//     KeyCorruptedError or KeyInvalidSizeError.
func ValidateKeyData(key []byte) error {
	// Check for empty key data
	if len(key) == 0 {
		return NewKeyCorruptedError("", fmt.Errorf("key data is empty"))
	}
	// Verify key matches expected Curve25519 key size
	if len(key) != KeySize {
		return NewKeyInvalidSizeError(KeySize, len(key))
	}
	return nil
}

// ValidateHexString validates that a string contains only valid hexadecimal
// characters and has an even length (required for proper byte representation).
// The validation is case-insensitive.
//
// Parameters:
//   - hexStr: The hexadecimal string to validate.
//
// Returns:
//   - error: nil if the string is valid hex; otherwise an InvalidInputError.
func ValidateHexString(hexStr string) error {
	// Empty string is not valid
	if hexStr == "" {
		return NewInvalidInputError("hex", "string is empty")
	}
	// Hex strings representing bytes must have even length
	if len(hexStr)%2 != 0 {
		return NewInvalidInputError("hex", "length must be even")
	}
	// Verify each character is a valid hex digit (0-9, a-f, case-insensitive)
	for _, c := range strings.ToLower(hexStr) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return NewInvalidInputError("hex", fmt.Sprintf("contains invalid character '%c'", c))
		}
	}
	return nil
}

// ValidateBase64String validates that a string is properly formatted standard
// Base64 by attempting to decode it. Uses the standard Base64 alphabet
// (with '+' and '/' characters).
//
// Parameters:
//   - base64Str: The Base64 string to validate.
//
// Returns:
//   - error: nil if the string is valid Base64; otherwise an InvalidInputError.
func ValidateBase64String(base64Str string) error {
	// Empty string is not valid
	if base64Str == "" {
		return NewInvalidInputError("base64", "string is empty")
	}
	// Attempt decoding to verify format correctness
	_, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return NewInvalidInputError("base64", fmt.Sprintf("decoding failed: %v", err))
	}
	return nil
}

// ValidateBase64URLString validates that a string is properly formatted
// URL-safe Base64 by attempting to decode it. Uses the URL-safe Base64
// alphabet (with '-' and '_' characters).
//
// Parameters:
//   - base64URLStr: The URL-safe Base64 string to validate.
//
// Returns:
//   - error: nil if the string is valid URL-safe Base64; otherwise an
//     InvalidInputError.
func ValidateBase64URLString(base64URLStr string) error {
	// Empty string is not valid
	if base64URLStr == "" {
		return NewInvalidInputError("base64url", "string is empty")
	}
	// Attempt decoding with URL-safe encoding to verify format
	_, err := base64.URLEncoding.DecodeString(base64URLStr)
	if err != nil {
		return NewInvalidInputError("base64url", fmt.Sprintf("decoding failed: %v", err))
	}
	return nil
}

// ValidateKeyFormat validates a key string against the expected encoding format.
// It delegates to the appropriate format-specific validator based on the
// encoding type.
//
// Parameters:
//   - keyStr: The encoded key string to validate.
//   - encoding: The expected encoding format (hex, base64, or base64url).
//
// Returns:
//   - error: nil if the key string matches the expected format; otherwise
//     an appropriate error describing the validation failure.
func ValidateKeyFormat(keyStr string, encoding EncodingType) error {
	// Empty string is never valid
	if keyStr == "" {
		return NewInvalidInputError("key", "string is empty")
	}

	// Delegate to format-specific validator
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

// ValidateEncryptedData validates that encrypted data is non-empty and meets
// a minimum size requirement. This is used as a quick sanity check before
// attempting decryption operations.
//
// Parameters:
//   - data: The encrypted data bytes to validate.
//   - minSize: The minimum acceptable size in bytes.
//
// Returns:
//   - error: nil if the data is valid; otherwise an InvalidCiphertextError.
func ValidateEncryptedData(data []byte, minSize int) error {
	// Reject empty data outright
	if len(data) == 0 {
		return NewInvalidCiphertextError("data is empty")
	}
	// Ensure data is at least the minimum expected size (header + some ciphertext)
	if len(data) < minSize {
		return NewInvalidCiphertextError(fmt.Sprintf("data length insufficient, expected at least %d bytes, got %d bytes", minSize, len(data)))
	}
	return nil
}

// IsNeptuneEncryptedFile determines whether a file has been encrypted with Neptune.
// It performs a two-tier check: first a fast extension-based check, then
// (if needed) a deeper inspection of the file header for the Neptune format
// version byte. Returns early if the file extension check passes.
//
// Parameters:
//   - filePath: The filesystem path of the file to check.
//
// Returns:
//   - bool: true if the file appears to be Neptune-encrypted; false otherwise.
//   - error: A NeptuneError if the file cannot be accessed or read.
func IsNeptuneEncryptedFile(filePath string) (bool, error) {
	// Tier 1: Fast check by file extension - if it ends in .ntp, assume encrypted
	if strings.HasSuffix(strings.ToLower(filePath), NeptuneFileExtension) {
		return true, nil
	}

	// Tier 2: Deeper check by examining file header
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, NewFileNotFoundError(filePath, err)
		}
		return false, NewFileReadError(filePath, err)
	}

	// File too small to contain a valid Neptune header - cannot be encrypted
	if info.Size() < NeptuneMinHeaderSize {
		return false, nil
	}

	// Open file to read the header bytes
	file, err := os.Open(filePath)
	if err != nil {
		return false, NewFileReadError(filePath, err)
	}
	defer file.Close()

	// Read the first NeptuneMinHeaderSize bytes as the file header
	header := make([]byte, NeptuneMinHeaderSize)
	n, err := file.Read(header)
	if err != nil {
		return false, NewFileReadError(filePath, err)
	}

	// Ensure we actually read the full header before inspecting it
	if n < NeptuneMinHeaderSize {
		return false, nil
	}

	// Check version byte (first byte of header). Currently only version 0x01
	// is supported, which identifies the Neptune encryption format.
	if header[0] == 0x01 {
		return true, nil
	}

	return false, nil
}

// ValidateNotEncrypted verifies that a file is not already Neptune-encrypted.
// If the file is already encrypted and forceOverride is false, it returns
// an error with a suggestion to use --force-override.
//
// Parameters:
//   - filePath: The filesystem path of the file to check.
//   - forceOverride: If true, bypasses the check and returns nil even if
//     the file is already encrypted.
//
// Returns:
//   - error: nil if the file is not encrypted (or forceOverride is true);
//     otherwise a FileAlreadyEncrypted error.
func ValidateNotEncrypted(filePath string, forceOverride bool) error {
	// Check if file is already encrypted with Neptune
	isEncrypted, err := IsNeptuneEncryptedFile(filePath)
	if err != nil {
		return err
	}

	if isEncrypted {
		// Allow forced override even if already encrypted
		if forceOverride {
			return nil
		}
		return &NeptuneError{
			Code:       ErrCodeFileAlreadyEncrypted,
			Message:    fmt.Sprintf("file is already encrypted: %s", filePath),
			Suggestion: "use --force-override flag to force encryption or check the input file",
		}
	}

	return nil
}

// ValidateVersion checks whether a given encryption format version byte
// is in the list of supported versions.
//
// Parameters:
//   - version: The version byte to validate.
//   - supportedVersions: A slice of version bytes that are considered valid.
//
// Returns:
//   - error: nil if the version is supported; otherwise an InvalidVersionError.
func ValidateVersion(version byte, supportedVersions []byte) error {
	// Linear search through supported versions (list is expected to be very small)
	for _, v := range supportedVersions {
		if version == v {
			return nil
		}
	}
	return NewInvalidVersionError(version)
}

// ValidateNonce validates that a nonce value is non-empty and has the
// expected byte length. Nonces are used in symmetric encryption to ensure
// that encrypting the same plaintext with the same key produces different
// ciphertexts.
//
// Parameters:
//   - nonce: The nonce bytes to validate.
//   - expectedSize: The expected length of the nonce in bytes
//     (e.g., 16 bytes for Sosemanuk).
//
// Returns:
//   - error: nil if the nonce is valid; otherwise an InvalidInputError.
func ValidateNonce(nonce []byte, expectedSize int) error {
	// Nonce must not be empty
	if len(nonce) == 0 {
		return NewInvalidInputError("nonce", "nonce is empty")
	}
	// Nonce must match the exact expected size for the cipher algorithm
	if len(nonce) != expectedSize {
		return NewInvalidInputError("nonce", fmt.Sprintf("invalid length，expected %d bytes，got %d bytes", expectedSize, len(nonce)))
	}
	return nil
}

// ValidateParameterNotEmpty validates that a string parameter is not empty.
// This is a generic helper for CLI parameter validation.
//
// Parameters:
//   - paramName: The name of the parameter (used in error messages).
//   - value: The parameter value to check.
//
// Returns:
//   - error: nil if the value is non-empty; otherwise a MissingInputError.
func ValidateParameterNotEmpty(paramName, value string) error {
	if value == "" {
		return NewMissingInputError(paramName)
	}
	return nil
}

// ValidateParameterInRange validates that an integer parameter falls within
// an inclusive range [min, max].
//
// Parameters:
//   - paramName: The name of the parameter (used in error messages).
//   - value: The integer value to validate.
//   - min: The minimum acceptable value (inclusive).
//   - max: The maximum acceptable value (inclusive).
//
// Returns:
//   - error: nil if the value is within range; otherwise an InvalidParameterError.
func ValidateParameterInRange(paramName string, value, min, max int) error {
	if value < min || value > max {
		return NewInvalidParameterError(paramName, fmt.Sprintf("%d", value), fmt.Sprintf("must be between %d and %d ", min, max))
	}
	return nil
}

// ValidateParameterPositive validates that an integer parameter is strictly
// positive (greater than zero).
//
// Parameters:
//   - paramName: The name of the parameter (used in error messages).
//   - value: The integer value to validate.
//
// Returns:
//   - error: nil if the value is positive; otherwise an InvalidParameterError.
func ValidateParameterPositive(paramName string, value int) error {
	if value <= 0 {
		return NewInvalidParameterError(paramName, fmt.Sprintf("%d", value), "must be positive")
	}
	return nil
}

// ValidateParameterPositive64 validates that an int64 parameter is strictly
// positive (greater than zero). This is the 64-bit variant of
// ValidateParameterPositive for use with larger numeric values.
//
// Parameters:
//   - paramName: The name of the parameter (used in error messages).
//   - value: The int64 value to validate.
//
// Returns:
//   - error: nil if the value is positive; otherwise an InvalidParameterError.
func ValidateParameterPositive64(paramName string, value int64) error {
	if value <= 0 {
		return NewInvalidParameterError(paramName, fmt.Sprintf("%d", value), "must be positive")
	}
	return nil
}

// ValidateFilePathIsWritable verifies that a file's parent directory is
// writable by performing an actual write test. It creates a temporary test
// file and immediately removes it, confirming the directory has write permissions.
//
// Parameters:
//   - path: The filesystem path of the file whose writability to check.
//
// Returns:
//   - error: nil if the parent directory is writable; otherwise a NeptuneError.
func ValidateFilePathIsWritable(path string) error {
	// Guard against empty path
	if path == "" {
		return NewInvalidPathError(path, fmt.Errorf("path is empty"))
	}

	// Resolve to absolute path for consistent handling
	absPath, err := filepath.Abs(path)
	if err != nil {
		return NewInvalidPathError(path, err)
	}

	// Check that the parent directory exists
	parentDir := filepath.Dir(absPath)
	parentInfo, err := os.Stat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return NewFileNotFoundError(parentDir, err)
		}
		return NewFileReadError(parentDir, err)
	}

	// Verify parent is actually a directory
	if !parentInfo.IsDir() {
		return NewInvalidPathError(parentDir, fmt.Errorf("parent path is not a directory"))
	}

	// Perform actual write test by creating and removing a temporary file
	testFile := filepath.Join(parentDir, ".neptune_test_write.tmp")
	f, err := os.Create(testFile)
	if err != nil {
		return NewFilePermissionError(parentDir, err)
	}
	f.Close()
	os.Remove(testFile)

	return nil
}

// ValidateKeyPairConsistency performs basic validation of a key pair by
// verifying that both the private and public keys have the correct byte size.
// Full cryptographic consistency (e.g., deriving the public key from the
// private key to verify they match) requires Curve25519 operations and is
// handled in the curve25519 package.
//
// Parameters:
//   - privateKey: The raw private key bytes to validate.
//   - publicKey: The raw public key bytes to validate.
//
// Returns:
//   - error: nil if both keys have valid sizes; otherwise the first error.
func ValidateKeyPairConsistency(privateKey, publicKey []byte) error {
	// Validate private key size
	if err := ValidateKeyData(privateKey); err != nil {
		return err
	}
	// Validate public key size
	if err := ValidateKeyData(publicKey); err != nil {
		return err
	}
	return nil
}

// ValidateInputData performs basic validation of input data for encryption
// or decryption operations. Currently only checks that the data is non-empty.
//
// Parameters:
//   - data: The input data bytes to validate.
//   - operation: The name of the operation (e.g., "encrypt", "decrypt"),
//     used in error messages for context.
//
// Returns:
//   - error: nil if the data is non-empty; otherwise an InvalidInputError.
func ValidateInputData(data []byte, operation string) error {
	if len(data) == 0 {
		return NewInvalidInputError(operation, "data is empty")
	}
	return nil
}

// ValidateEncodingFormat validates an encoding format string by attempting
// to parse it as an EncodingType. This is a convenience wrapper around
// ParseEncodingType for validation-only use cases.
//
// Parameters:
//   - encoding: The encoding format string to validate ("hex", "base64", "base64url").
//
// Returns:
//   - error: nil if the encoding is valid; otherwise an error describing the failure.
func ValidateEncodingFormat(encoding string) error {
	_, err := ParseEncodingType(encoding)
	return err
}

// ValidateAllParameters validates a collection of parameters of various types
// in a single pass. It returns all validation errors found, rather than stopping
// at the first error. Supported types are: string, int, int64, []byte, and nil.
//
// Parameters:
//   - params: A map where keys are parameter names and values are the parameter
//     values to validate.
//
// Returns:
//   - []error: A slice of errors, one for each parameter that failed validation.
//     The slice is empty if all parameters are valid.
func ValidateAllParameters(params map[string]interface{}) []error {
	var errs []error

	// Validate each parameter based on its type
	for name, value := range params {
		switch v := value.(type) {
		case string:
			// String parameters must not be empty
			if v == "" {
				errs = append(errs, NewMissingInputError(name))
			}
		case int:
			// Int parameters must be positive
			if v <= 0 {
				errs = append(errs, NewInvalidParameterError(name, fmt.Sprintf("%d", v), "must be positive"))
			}
		case int64:
			// Int64 parameters must be positive
			if v <= 0 {
				errs = append(errs, NewInvalidParameterError(name, fmt.Sprintf("%d", v), "must be positive"))
			}
		case []byte:
			// Byte slice parameters must not be empty
			if len(v) == 0 {
				errs = append(errs, NewInvalidInputError(name, "data is empty"))
			}
		case nil:
			// Nil values are treated as missing
			errs = append(errs, NewMissingInputError(name))
		}
	}

	return errs
}

// FindFilesRecursively walks a directory tree and returns a list of matching
// files. It supports include and exclude glob patterns, gracefully handles
// permission errors and file-in-use conditions, and skips recycle bin directories.
//
// Parameters:
//   - dirPath: The root directory path to start the recursive search from.
//   - includePatterns: Glob patterns for file names to include. If empty, all
//     files are included (subject to exclude patterns).
//   - excludePatterns: Glob patterns for file names to exclude from results.
//
// Returns:
//   - []string: A slice of file paths that match the include/exclude criteria.
//   - error: Always returns nil; walk errors are logged as warnings and skipped.
func FindFilesRecursively(dirPath string, includePatterns, excludePatterns []string) ([]string, error) {
	var files []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		// Handle errors encountered while walking the directory tree
		if err != nil {
			// Permission denied: skip this directory with a warning
			if os.IsPermission(err) {
				PrintWarning("Permission denied: %s", path)
				return filepath.SkipDir
			}
			// Path not found: skip silently
			if strings.Contains(err.Error(), "cannot find the path") ||
				strings.Contains(err.Error(), "not exist") ||
				strings.Contains(err.Error(), "cannot find the file") {
				return filepath.SkipDir
			}
			// File in use / sharing violation: skip with a warning
			if strings.Contains(err.Error(), "sharing violation") ||
				strings.Contains(err.Error(), "in use") {
				PrintWarning("File in use: %s", path)
				return nil
			}
			// Other errors: warn and skip directory
			PrintWarning("Error accessing %s: %v", path, err)
			return filepath.SkipDir
		}

		// Handle directories
		if info.IsDir() {
			// Skip Windows recycle bin directories
			dirName := strings.ToLower(filepath.Base(path))
			if dirName == "$recycle.bin" || dirName == "recycler" {
				return filepath.SkipDir
			}
			return nil
		}

		// Apply exclusion patterns first (exclusions take priority)
		for _, pattern := range excludePatterns {
			if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
				return nil
			}
		}

		// Apply inclusion patterns if any are specified
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

		// File passed all filters - add to results
		files = append(files, path)
		return nil
	})

	// Log any top-level walk error but continue (non-fatal)
	if err != nil {
		PrintWarning("Error walking directory %s: %v", dirPath, err)
	}

	return files, nil
}

// GetRelativePathFromBase computes the relative path from a base directory
// to a target path. Both paths are resolved to their absolute form before
// the relative path calculation.
//
// Parameters:
//   - base: The base directory path from which to compute the relative path.
//   - target: The target file or directory path.
//
// Returns:
//   - string: The relative path from base to target.
//   - error: A NeptuneError if either path cannot be resolved.
func GetRelativePathFromBase(base, target string) (string, error) {
	// Resolve base path to absolute form
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", NewInvalidPathError(base, err)
	}
	// Resolve target path to absolute form
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", NewInvalidPathError(target, err)
	}
	return filepath.Rel(baseAbs, targetAbs)
}

// EnsureParentDirectory ensures that the parent directory of a given file path
// exists, creating it if necessary. Root paths (".", "/", "\") are treated as
// already existing and are not created.
//
// Parameters:
//   - filePath: The file path whose parent directory should be ensured.
//
// Returns:
//   - error: nil if the parent directory exists or was created successfully.
func EnsureParentDirectory(filePath string) error {
	// Extract the parent directory from the file path
	parentDir := filepath.Dir(filePath)
	// Root and current directory are assumed to always exist
	if parentDir == "." || parentDir == "/" || parentDir == "\\" {
		return nil
	}
	return EnsureDirectory(parentDir)
}

// CopyDirectoryRecursively copies an entire directory tree from source to
// destination. It recursively creates subdirectories and copies all files.
// Existing files in the destination are overwritten.
//
// Parameters:
//   - src: The source directory path to copy from.
//   - dst: The destination directory path to copy to.
//
// Returns:
//   - error: nil if the copy succeeds; otherwise a NeptuneError.
func CopyDirectoryRecursively(src, dst string) error {
	// Verify source path exists and is a directory
	srcInfo, err := os.Stat(src)
	if err != nil {
		return NewFileReadError(src, err)
	}

	if !srcInfo.IsDir() {
		return NewInvalidPathError(src, fmt.Errorf("source path is not a directory"))
	}

	// Ensure destination directory exists
	if err := EnsureDirectory(dst); err != nil {
		return err
	}

	// List all entries in the source directory
	entries, err := os.ReadDir(src)
	if err != nil {
		return NewFileReadError(src, err)
	}

	// Recursively copy each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectory
			if err := CopyDirectoryRecursively(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy individual file with overwrite enabled
			if err := CopyFile(srcPath, dstPath, true); err != nil {
				return err
			}
		}
	}

	return nil
}

// DeleteEmptyDirectories recursively traverses a directory tree and removes
// any directories that are empty. It processes subdirectories first (post-order
// traversal) so that nested empty directories are cleaned up bottom-up.
//
// Parameters:
//   - dirPath: The root directory path to clean up.
//
// Returns:
//   - error: nil if the operation succeeds; otherwise a NeptuneError.
func DeleteEmptyDirectories(dirPath string) error {
	// First pass: recursively process all subdirectories
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

	// Second pass: check if this directory is now empty after cleanup
	entries, err = os.ReadDir(dirPath)
	if err != nil {
		return NewFileReadError(dirPath, err)
	}

	// Remove the directory if it's empty
	if len(entries) == 0 {
		if err := os.Remove(dirPath); err != nil {
			return NewFileDeleteError(dirPath, err)
		}
	}

	return nil
}

// DefaultHTTPTimeout is the default timeout duration for HTTP requests
// initiated by the download utilities. Set to 30 seconds to accommodate
// typical network conditions while preventing indefinite hangs.
const DefaultHTTPTimeout = 30 * time.Second

// IsHTTPURL checks whether a string represents a valid HTTP or HTTPS URL
// by parsing it and inspecting the scheme component.
//
// Parameters:
//   - s: The string to check.
//
// Returns:
//   - bool: true if the string has an http or https scheme; false otherwise.
func IsHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// DownloadFile downloads a file from an HTTP/HTTPS URL and saves it to a
// local file path. It validates the URL, enforces a timeout, limits redirects,
// checks the HTTP response status, and ensures the output directory exists.
//
// Parameters:
//   - urlStr: The HTTP/HTTPS URL to download from.
//   - outputPath: The local filesystem path where the downloaded file will be saved.
//   - timeout: The maximum duration for the entire download operation.
//
// Returns:
//   - error: nil if the download succeeds; otherwise a NeptuneError describing
//     the failure with a suggested remedy.
func DownloadFile(urlStr, outputPath string, timeout time.Duration) error {
	// Validate URL format
	if !IsHTTPURL(urlStr) {
		return NewInvalidInputError("url", "invalid HTTP/HTTPS URL")
	}

	// Configure HTTP client with timeout and redirect limits
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Limit redirects to prevent infinite redirect loops
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Execute HTTP GET request
	resp, err := client.Get(urlStr)
	if err != nil {
		return NewFileReadError(urlStr, err)
	}
	defer resp.Body.Close()

	// Verify successful HTTP response
	if resp.StatusCode != http.StatusOK {
		return &NeptuneError{
			Code:   ErrCodeFileReadFailed,
			Message: fmt.Sprintf("download failed: HTTP %d", resp.StatusCode),
			Suggestion: "check if the URL is correct and ensure the resource is accessible",
		}
	}

	// Ensure the output directory exists before writing
	if err := EnsureParentDirectory(outputPath); err != nil {
		return err
	}

	// Create output file
	out, err := os.Create(outputPath)
	if err != nil {
		return NewFileWriteError(outputPath, err)
	}
	defer out.Close()

	// Stream the response body directly to the file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return NewFileWriteError(outputPath, err)
	}

	return nil
}

// DownloadToTempFile downloads a file from a URL to a temporary file with a
// "neptune_" prefix and returns the path to the temporary file. The caller
// is responsible for removing the temporary file when it is no longer needed.
// If the download fails, the temporary file is cleaned up automatically.
//
// Parameters:
//   - urlStr: The HTTP/HTTPS URL to download from.
//   - timeout: The maximum duration for the entire download operation.
//
// Returns:
//   - string: The filesystem path of the downloaded temporary file.
//   - error: A NeptuneError if the download fails.
func DownloadToTempFile(urlStr string, timeout time.Duration) (string, error) {
	// Validate URL format
	if !IsHTTPURL(urlStr) {
		return "", NewInvalidInputError("url", "invalid HTTP/HTTPS URL")
	}

	// Create a temporary file with a unique name
	tempFile, err := os.CreateTemp("", "neptune_*.tmp")
	if err != nil {
		return "", NewFileCreateError("", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()

	// Download to the temporary file
	if err := DownloadFile(urlStr, tempPath, timeout); err != nil {
		// Clean up temp file on failure
		os.Remove(tempPath)
		return "", err
	}

	return tempPath, nil
}

// DownloadBytes downloads content from a URL and returns it as an in-memory
// byte slice. Similar to DownloadFile but stores the result in memory rather
// than writing to disk. Useful for downloading small files or configuration data.
//
// Parameters:
//   - urlStr: The HTTP/HTTPS URL to download from.
//   - timeout: The maximum duration for the entire download operation.
//
// Returns:
//   - []byte: The downloaded content as a byte slice.
//   - error: A NeptuneError if the download fails.
func DownloadBytes(urlStr string, timeout time.Duration) ([]byte, error) {
	// Validate URL format
	if !IsHTTPURL(urlStr) {
		return nil, NewInvalidInputError("url", "invalid HTTP/HTTPS URL")
	}

	// Configure HTTP client with timeout and redirect limits
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Execute HTTP GET request
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, NewFileReadError(urlStr, err)
	}
	defer resp.Body.Close()

	// Verify successful HTTP response
	if resp.StatusCode != http.StatusOK {
		return nil, &NeptuneError{
			Code:   ErrCodeFileReadFailed,
			Message: fmt.Sprintf("download failed: HTTP %d", resp.StatusCode),
			Suggestion: "check if the URL is correct and ensure the resource is accessible",
		}
	}

	// Read entire response body into memory
	return io.ReadAll(resp.Body)
}

// ExtractFileNameFromURL extracts a file name from the path component of a URL.
// If the URL cannot be parsed or the path does not yield a meaningful file name,
// it returns the default value "downloaded".
//
// Parameters:
//   - urlStr: The URL string to extract a file name from.
//
// Returns:
//   - string: The extracted file name, or "downloaded" as a fallback.
func ExtractFileNameFromURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "downloaded"
	}
	// Get the last segment of the URL path as the filename
	path := u.Path
	filename := filepath.Base(path)
	// Fall back to default if the path doesn't contain a valid filename
	if filename == "." || filename == "/" || filename == "" {
		return "downloaded"
	}
	return filename
}

// BufferPool provides a pool of reusable byte buffers backed by sync.Pool.
// By reusing buffers instead of allocating new ones, it reduces memory
// allocation overhead and garbage collection pressure during high-throughput
// operations like streaming encryption and decryption.
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new BufferPool with a default buffer size of 4KB.
// Buffers allocated by the pool start with length 0 and capacity 4096.
//
// Returns:
//   - *BufferPool: A pointer to the newly created buffer pool.
func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, 4096)
			},
		},
	}
}

// NewBufferPoolWithSize creates a new BufferPool with a custom default buffer size.
// Buffers allocated by the pool start with length 0 and the specified capacity.
//
// Parameters:
//   - defaultSize: The default capacity in bytes for newly allocated buffers.
//
// Returns:
//   - *BufferPool: A pointer to the newly created buffer pool.
func NewBufferPoolWithSize(defaultSize int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, defaultSize)
			},
		},
	}
}

// GetBuffer retrieves a byte buffer from the pool with at least the requested
// capacity. If the pool has no available buffers or the available buffer is
// too small, a new buffer is allocated. The returned buffer has length 0
// and is ready for use with append or slicing.
//
// Parameters:
//   - size: The minimum required capacity for the buffer in bytes.
//
// Returns:
//   - []byte: A zero-length byte slice with capacity >= size.
func (bp *BufferPool) GetBuffer(size int) []byte {
	buf := bp.pool.Get().([]byte)
	// If pooled buffer is too small, allocate a new one instead
	if cap(buf) < size {
		return make([]byte, 0, size)
	}
	// Reset buffer length to 0 while preserving capacity
	return buf[:0]
}

// PutBuffer returns a byte buffer back to the pool for reuse. The buffer's
// length is reset to 0 before being returned. Callers must not continue to
// reference the buffer after returning it to the pool.
//
// Parameters:
//   - buf: The byte slice to return to the pool. Nil buffers are ignored.
func (bp *BufferPool) PutBuffer(buf []byte) {
	if buf == nil {
		return
	}
	// Reset length to 0 before returning to pool
	buf = buf[:0]
	bp.pool.Put(buf)
}

// GetBufferDefault retrieves a default-sized (4KB) buffer from the pool.
// This is a convenience wrapper around GetBuffer with the standard 4KB size.
//
// Returns:
//   - []byte: A zero-length byte slice with at least 4KB capacity.
func (bp *BufferPool) GetBufferDefault() []byte {
	return bp.GetBuffer(4096)
}

// globalBufferPool is a package-level shared buffer pool instance used by
// utilities that need temporary buffers without managing their own pool.
// It is initialized with the default 4KB buffer size.
var globalBufferPool = NewBufferPool()

// GetGlobalBuffer retrieves a buffer from the global shared buffer pool.
// This provides convenient access to a shared pool for one-off buffer needs.
//
// Parameters:
//   - size: The minimum required capacity for the buffer in bytes.
//
// Returns:
//   - []byte: A zero-length byte slice with capacity >= size.
func GetGlobalBuffer(size int) []byte {
	return globalBufferPool.GetBuffer(size)
}

// PutGlobalBuffer returns a buffer to the global shared buffer pool.
// Callers must not continue to reference the buffer after returning it.
//
// Parameters:
//   - buf: The byte slice to return to the global pool.
func PutGlobalBuffer(buf []byte) {
	globalBufferPool.PutBuffer(buf)
}

// ParseChunkSize parses a human-readable chunk size string into an integer
// byte count. Supported units are B, KB, MB, and GB (case-insensitive).
// Decimal values are accepted and truncated to integer bytes.
//
// Parameters:
//   - sizeStr: A string like "64KB", "1MB", "4MB", "1GB", or "1024B".
//
// Returns:
//   - int: The size in bytes on success.
//   - error: An InvalidInputError if the string cannot be parsed, is negative,
//     or exceeds the maximum int value.
func ParseChunkSize(sizeStr string) (int, error) {
	if sizeStr == "" {
		return 0, NewInvalidInputError("size", "string is empty")
	}

	// Regex captures a numeric value (with optional decimal) and an optional unit
	re := regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(KB|MB|GB|B)?$`)
	matches := re.FindStringSubmatch(strings.ToUpper(sizeStr))

	if matches == nil {
		return 0, NewInvalidInputError("size", fmt.Sprintf("invalid size format: %s，supported formats: 64KB, 1MB, 4MB, 1GB", sizeStr))
	}

	// Parse the numeric portion as a float to support decimal values
	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, NewInvalidInputError("size", fmt.Sprintf("cannot parse numeric value: %s", matches[1]))
	}

	if value < 0 {
		return 0, NewInvalidInputError("size", "size cannot be negative")
	}

	// Convert to byte count based on the unit suffix
	unit := matches[2]
	var bytes int64

	switch unit {
	case "", "B":
		bytes = int64(value)
	case "KB":
		bytes = int64(value * 1024)
	case "MB":
		bytes = int64(value * 1024 * 1024)
	case "GB":
		bytes = int64(value * 1024 * 1024 * 1024)
	default:
		return 0, NewInvalidInputError("size", fmt.Sprintf("unsupported unit: %s", unit))
	}

	// Ensure the result fits in an int (prevents overflow on 32-bit systems)
	if bytes > int64(1<<31-1) {
		return 0, NewInvalidInputError("size", fmt.Sprintf("size exceeds limit: %d bytes", bytes))
	}

	return int(bytes), nil
}

// FormatChunkSize converts a raw byte count into a compact human-readable
// string without spaces (e.g., "1.50MB" instead of "1.50 MB"). Uses the
// largest appropriate unit for readability.
//
// Parameters:
//   - bytes: The size in bytes as an int.
//
// Returns:
//   - string: A formatted size string (e.g., "64KB", "1.50MB", "2GB").
func FormatChunkSize(bytes int) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2fGB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2fMB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2fKB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

// ValidateChunkSize checks that a chunk size value falls within the accepted
// range of 1KB minimum to 100MB maximum. Chunk sizes outside this range
// are considered unreasonable for streaming encryption operations.
//
// Parameters:
//   - size: The chunk size in bytes to validate.
//
// Returns:
//   - error: nil if the chunk size is valid; otherwise an InvalidParameterError.
func ValidateChunkSize(size int) error {
	const (
		MinChunkSize = 1024
		MaxChunkSize = 100 * 1024 * 1024
	)

	if size < MinChunkSize {
		return NewInvalidParameterError("chunk-size", fmt.Sprintf("%d", size),
			fmt.Sprintf("chunk size cannot be less than %s", FormatChunkSize(MinChunkSize)))
	}

	if size > MaxChunkSize {
		return NewInvalidParameterError("chunk-size", fmt.Sprintf("%d", size),
			fmt.Sprintf("chunk size cannot exceed %s", FormatChunkSize(MaxChunkSize)))
	}

	return nil
}

// GenerateRandomFilename generates a random file name while preserving the
// original file's directory and extension. The random portion is a 16-byte
// cryptographically random value encoded as 32 hexadecimal characters.
//
// Parameters:
//   - originalPath: The original file path from which to derive the directory and extension.
//
// Returns:
//   - string: A new file path with a random base name and the original extension.
func GenerateRandomFilename(originalPath string) string {
	dir := filepath.Dir(originalPath)
	ext := filepath.Ext(originalPath)

	b := make([]byte, 16)
	cryptoRand.Read(b)

	randomName := hex.EncodeToString(b)

	return filepath.Join(dir, randomName+ext)
}

// GenerateRandomString generates a random hexadecimal string of the specified
// length using cryptographically secure random bytes. The resulting string
// will have approximately length/2 bytes of entropy (each byte encodes to
// two hex characters).
//
// Parameters:
//   - length: The desired length of the output string in characters.
//
// Returns:
//   - string: A random hexadecimal string of the specified length.
func GenerateRandomString(length int) string {
	b := make([]byte, length/2)
	cryptoRand.Read(b)
	return hex.EncodeToString(b)
}

// RandomDelay sleeps for a random duration between minMs and maxMs milliseconds.
// The random value is derived from cryptographically secure random bytes.
// If minMs is greater than or equal to maxMs, it sleeps for exactly minMs.
//
// Parameters:
//   - minMs: The minimum delay in milliseconds.
//   - maxMs: The maximum delay in milliseconds.
func RandomDelay(minMs, maxMs int) {
	// If range is invalid or zero-width, use min directly
	if minMs >= maxMs {
		time.Sleep(time.Duration(minMs) * time.Millisecond)
		return
	}

	// Generate 4 random bytes for a sufficiently random delay value
	b := make([]byte, 4)
	cryptoRand.Read(b)

	// Compute random delay within range using modulo on the product of random bytes
	delayMs := minMs + int(uint32(b[0])*uint32(b[1])*uint32(b[2])*uint32(b[3]))%(maxMs-minMs)

	time.Sleep(time.Duration(delayMs) * time.Millisecond)
}