// Package cmd provides command-line commands for the neptune CLI tool.
// This file implements the "download" command, which allows users to
// download files from remote HTTP/HTTPS URLs with support for multiple
// files, custom output paths, and secure memory cleanup.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"neptune/internal/utils"
)

var (
	// downloadRemoteURL holds the list of remote URLs to download.
	// It is populated by the --remote-url flag, which can be specified
	// multiple times to download several files in a single command.
	downloadRemoteURL []string

	// downloadOutput specifies the destination for downloaded files.
	// When downloading a single file, it can be either a directory path
	// or a full file path (to rename the file). When downloading multiple
	// files, it must be a directory path.
	downloadOutput string

	// downloadTimeout is the HTTP request timeout in seconds for each
	// download operation. Defaults to 30 seconds; a value of 0 or less
	// causes the default timeout from utils.DefaultHTTPTimeout to be used.
	downloadTimeout int
)

// downloadCmd is the cobra command that handles downloading files from
// remote URLs. It supports multiple file downloads, custom output paths,
// and configurable timeouts.
//
// Usage examples:
//   - Download a single file to a directory
//   - Download multiple files to a directory
//   - Download and rename a single file
var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download remote files",
	Long: `Download files from remote URLs (HTTP/HTTPS).

Supports downloading multiple files at once.

Examples:
  # Download a single file
  neptune download --remote-url https://example.com/file.pdf --output ./downloads/

  # Download multiple files
  neptune download --remote-url https://example.com/file1.pdf --remote-url https://example.com/file2.txt --output ./downloads/

  # Download and rename
  neptune download --remote-url https://example.com/file.pdf --output ./myfile.pdf`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate that at least one remote URL was provided.
		if len(downloadRemoteURL) == 0 {
			return utils.NewMissingInputError("remote-url")
		}

		// Validate each URL is a valid HTTP or HTTPS URL.
		for _, url := range downloadRemoteURL {
			if !utils.IsHTTPURL(url) {
				return &utils.NeptuneError{
					Code:       utils.ErrCodeInvalidInput,
					Message:    fmt.Sprintf(" URL: %s", url),
					Suggestion: "--remote-url  HTTP/HTTPS URL",
				}
			}
		}

		// When multiple URLs are provided, the output path must be a directory
		// (not a single file path), since each downloaded file retains its own name.
		if len(downloadRemoteURL) > 1 && downloadOutput != "" {
			info, err := os.Stat(downloadOutput)
			if err == nil && !info.IsDir() {
				return &utils.NeptuneError{
					Code:       utils.ErrCodeInvalidInput,
					Message:    " --remote-url ，--output ",
					Suggestion: "， --remote-url",
				}
			}
		}

		// Set timeout duration from the flag value. If the flag value is zero
		// or negative, fall back to the application's default HTTP timeout.
		timeout := time.Duration(downloadTimeout) * time.Second
		if timeout <= 0 {
			timeout = utils.DefaultHTTPTimeout
		}

		return downloadFiles(downloadRemoteURL, downloadOutput, timeout)
	},
}

// downloadFiles downloads one or more files from the given URLs and saves them
// to the specified output directory or file path.
//
// Parameters:
//   - urls: a slice of HTTP/HTTPS URLs pointing to the files to download.
//   - outputDir: the destination path. If it is an existing directory, each
//     file is saved inside it with its original filename from the URL. If it
//     is a non-directory path (or does not exist) and only one URL is given,
//     it is used as the full output file path. If empty, files are saved in
//     the current working directory.
//   - timeout: the HTTP request timeout for each individual download.
//
// Returns:
//   - nil always (errors for individual files are printed and counted,
//     but do not stop the remaining downloads or cause the function to
//     return an error).
//
// The function prints progress, success, and error messages for each file.
// After each successful download, the in-memory data buffer is securely
// zeroed to prevent sensitive data from lingering in memory.
func downloadFiles(urls []string, outputDir string, timeout time.Duration) error {
	successCount := 0
	failedCount := 0

	for _, url := range urls {
		// Derive the filename from the last segment of the URL path.
		filename := utils.ExtractFileNameFromURL(url)
		utils.PrintInfo("Downloading file: %s", filename)

		// Download the file content into memory as a byte slice.
		data, err := utils.DownloadBytes(url, timeout)
		if err != nil {
			utils.PrintError("Download failed: %s", err.Error())
			failedCount++
			continue
		}

		// Determine the final output path for the downloaded file.
		var outputPath string

		if outputDir != "" {
			// If the output path is an existing directory, join the filename
			// to produce the full output path. Otherwise, treat outputDir as
			// a full file path (used for renaming a single-file download).
			info, err := os.Stat(outputDir)
			if err == nil && info.IsDir() {
				outputPath = filepath.Join(outputDir, filename)
			} else {
				outputPath = outputDir
			}
		} else {
			// No output specified: save with the original filename in the
			// current working directory.
			outputPath = filename
		}

		// Ensure the parent directory of the output path exists, creating it
		// if necessary.
		if err := utils.EnsureParentDirectory(outputPath); err != nil {
			utils.PrintError("Failed to create directory: %s", err.Error())
			failedCount++
			continue
		}

		// Write the downloaded bytes to the output file with standard
		// read/write permissions (0644).
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			utils.PrintError("Failed to write file: %s", err.Error())
			failedCount++
			continue
		}

		utils.PrintSuccess("Download completed: %s -> %s (%s)", filename, outputPath, utils.FormatFileSize(int64(len(data))))

		// ========== Memory cleanup: clear downloaded data ==========
		// Securely zero out the byte slice containing the downloaded data
		// so that sensitive file contents do not remain resident in memory
		// after the download is complete.
		utils.PrintInfo("[Memory] Clearing downloaded data (%d bytes)...", len(data))
		utils.SecureZeroMemory(data)
		utils.PrintSuccess("[Memory] Downloaded data cleared from memory")

		successCount++
	}

	// Print a summary of how many downloads succeeded and how many failed.
	utils.PrintInfo("Download completed: %d success, %d failed", successCount, failedCount)

	return nil
}

// init registers the download command with the root command and defines
// its command-line flags.
//
// Flags:
//   - --remote-url: (required, repeatable) the remote URL(s) to download.
//   - --output / -o: the output directory or file path.
//   - --timeout: HTTP request timeout in seconds (default 30).
func init() {
	rootCmd.AddCommand(downloadCmd)

	downloadCmd.Flags().StringArrayVar(&downloadRemoteURL, "remote-url", []string{}, "Remote URL to download (HTTP/HTTPS, can be used multiple times)")
	downloadCmd.Flags().StringVarP(&downloadOutput, "output", "o", "", "Output directory or file path")
	downloadCmd.Flags().IntVar(&downloadTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")

	downloadCmd.MarkFlagRequired("remote-url")
}
