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
	downloadRemoteURL []string
	downloadOutput    string
	downloadTimeout   int
)

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
		if len(downloadRemoteURL) == 0 {
			return utils.NewMissingInputError("remote-url")
		}

		//  URL
		for _, url := range downloadRemoteURL {
			if !utils.IsHTTPURL(url) {
				return &utils.NeptuneError{
					Code:       utils.ErrCodeInvalidInput,
					Message:    fmt.Sprintf(" URL: %s", url),
					Suggestion: "--remote-url  HTTP/HTTPS URL",
				}
			}
		}

		//  URL ，
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

		// Set timeout
		timeout := time.Duration(downloadTimeout) * time.Second
		if timeout <= 0 {
			timeout = utils.DefaultHTTPTimeout
		}

		return downloadFiles(downloadRemoteURL, downloadOutput, timeout)
	},
}

func downloadFiles(urls []string, outputDir string, timeout time.Duration) error {
	successCount := 0
	failedCount := 0

	for _, url := range urls {
		utils.PrintInfo("Downloading: %s", url)
		data, err := utils.DownloadBytes(url, timeout)
		if err != nil {
			utils.PrintError("Download failed: %s", err.Error())
			failedCount++
			continue
		}

		filename := utils.ExtractFileNameFromURL(url)
		var outputPath string

		if outputDir != "" {
			info, err := os.Stat(outputDir)
			if err == nil && info.IsDir() {
				outputPath = filepath.Join(outputDir, filename)
			} else {
				outputPath = outputDir
			}
		} else {
			outputPath = filename
		}

		// Ensure parent directory exists
		if err := utils.EnsureParentDirectory(outputPath); err != nil {
			utils.PrintError("Failed to create directory: %s", err.Error())
			failedCount++
			continue
		}

		// Write file
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			utils.PrintError("Failed to write file: %s", err.Error())
			failedCount++
			continue
		}

		utils.PrintSuccess("Downloaded: %s -> %s (%s)", filename, outputPath, utils.FormatFileSize(int64(len(data))))

		// ========== Memory cleanup: clear downloaded data ==========
		utils.PrintInfo("[Memory] Clearing downloaded data (%d bytes)...", len(data))
		utils.SecureZeroMemory(data)
		utils.PrintSuccess("[Memory] Downloaded data cleared from memory")

		successCount++
	}

	utils.PrintInfo("Download completed: %d success, %d failed", successCount, failedCount)

	return nil
}

func init() {
	rootCmd.AddCommand(downloadCmd)

	downloadCmd.Flags().StringArrayVar(&downloadRemoteURL, "remote-url", []string{}, "Remote URL to download (HTTP/HTTPS, can be used multiple times)")
	downloadCmd.Flags().StringVarP(&downloadOutput, "output", "o", "", "Output directory or file path")
	downloadCmd.Flags().IntVar(&downloadTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")

	downloadCmd.MarkFlagRequired("remote-url")
}