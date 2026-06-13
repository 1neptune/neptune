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

		// 验证远程 URL
		for _, url := range downloadRemoteURL {
			if !utils.IsHTTPURL(url) {
				return &utils.NeptuneError{
					Code:       utils.ErrCodeInvalidInput,
					Message:    fmt.Sprintf("无效的 URL: %s", url),
					Suggestion: "--remote-url 参数只支持 HTTP/HTTPS URL",
				}
			}
		}

		// 多个远程 URL 时，输出必须是目录
		if len(downloadRemoteURL) > 1 && downloadOutput != "" {
			info, err := os.Stat(downloadOutput)
			if err == nil && !info.IsDir() {
				return &utils.NeptuneError{
					Code:       utils.ErrCodeInvalidInput,
					Message:    "当使用多个 --remote-url 时，--output 必须是目录",
					Suggestion: "请指定一个目录作为输出，或使用单个 --remote-url",
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
		utils.PrintInfo("正在下载: %s", url)
		data, err := utils.DownloadBytes(url, timeout)
		if err != nil {
			utils.PrintError("下载失败: %s", err.Error())
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
			utils.PrintError("创建目录失败: %s", err.Error())
			failedCount++
			continue
		}

		// Write file
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			utils.PrintError("写入文件失败: %s", err.Error())
			failedCount++
			continue
		}

		utils.PrintSuccess("下载完成: %s -> %s (%s)", filename, outputPath, utils.FormatFileSize(int64(len(data))))
		successCount++
	}

	utils.PrintInfo("下载完成: %d 成功, %d 失败", successCount, failedCount)

	if failedCount > 0 {
		return fmt.Errorf("部分文件下载失败")
	}

	return nil
}

func init() {
	rootCmd.AddCommand(downloadCmd)

	downloadCmd.Flags().StringArrayVar(&downloadRemoteURL, "remote-url", []string{}, "Remote URL to download (HTTP/HTTPS, can be used multiple times)")
	downloadCmd.Flags().StringVarP(&downloadOutput, "output", "o", "", "Output directory or file path")
	downloadCmd.Flags().IntVar(&downloadTimeout, "timeout", 30, "HTTP request timeout in seconds (default: 30)")

	downloadCmd.MarkFlagRequired("remote-url")
}