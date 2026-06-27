//go:build windows

// Package utils (Windows-specific) provides disk and directory enumeration
// utilities tailored for the Windows operating system. These functions use
// Windows API calls via the golang.org/x/sys/windows package to enumerate
// logical drives and retrieve top-level directories, including special
// handling for user profile directories.
package utils

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// getLogicalDrives retrieves a list of all logical drives on the Windows system
// by calling the GetLogicalDriveStrings Windows API function. The returned
// strings are drive root paths in the format "C:\", "D:\", etc.
//
// Returns:
//   - []string: A slice of drive root paths (e.g., ["C:\\", "D:\\", "E:\\"]).
//   - error: An error if the Windows API call fails.
func getLogicalDrives() ([]string, error) {
	// Allocate buffer for up to 26 drives (A-Z), each with 4 UTF-16 chars
	// (e.g., "C:\\" is 3 characters plus null terminator)
	driveStrings := make([]uint16, 26*4)
	n, err := windows.GetLogicalDriveStrings(uint32(len(driveStrings)), &driveStrings[0])
	if err != nil {
		return nil, err
	}

	// No drives found - return empty slice
	if n == 0 {
		return []string{}, nil
	}

	// Parse the double-null-terminated string buffer into individual drive paths
	var drives []string
	for i := 0; i < len(driveStrings) && driveStrings[i] != 0; {
		// Find the end of the current drive string (null terminator)
		end := i
		for end < len(driveStrings) && driveStrings[end] != 0 {
			end++
		}
		// Convert the UTF-16 substring to a Go string
		if end > i {
			drivePath := windows.UTF16ToString(driveStrings[i:end])
			drives = append(drives, drivePath)
		}
		// Move past the null terminator to the next string
		i = end + 1
	}

	return drives, nil
}

// GetAllDisks retrieves all available logical drives on the Windows system,
// excluding the C:\ drive. This is used to enumerate disks for bulk operations
// while avoiding the system drive.
//
// Returns:
//   - []string: A slice of drive root paths excluding "C:\\".
//   - error: An error if the drive enumeration fails.
func GetAllDisks() ([]string, error) {
	// Get all logical drives from the system
	drives, err := getLogicalDrives()
	if err != nil {
		return nil, err
	}

	// Filter out the C:\ system drive
	var filteredDrives []string
	for _, drive := range drives {
		if strings.ToUpper(drive) != "C:\\" {
			filteredDrives = append(filteredDrives, drive)
		}
	}

	return filteredDrives, nil
}

// GetAllDesktopDirectories retrieves all users' Desktop directories from C:\Users.
// This function enumerates user profiles under C:\Users and returns only the
// Desktop directories that actually exist. This is used when disk-scan mode
// should focus exclusively on user desktop directories rather than scanning
// all disks.
//
// Returns:
//   - []string: A slice of Desktop directory paths (e.g., ["C:\\Users\\John\\Desktop", "C:\\Users\\Jane\\Desktop"]).
//   - error: An error if the C:\Users directory cannot be accessed.
func GetAllDesktopDirectories() ([]string, error) {
	var desktopDirs []string

	usersDir := "C:\\Users"
	userDirs, err := GetDirectories(usersDir)
	if err != nil {
		return nil, err
	}

	for _, userDir := range userDirs {
		desktopDir := filepath.Join(userDir, "Desktop")
		if _, err := os.Stat(desktopDir); err == nil {
			desktopDirs = append(desktopDirs, desktopDir)
		}
	}

	return desktopDirs, nil
}

// GetTopLevelDirectories retrieves the top-level directories from a given
// disk path, excluding system recycle bin directories.
// Recycle bin directories ($recycle.bin, recycler) are skipped to avoid
// scanning system-protected folders.
//
// Parameters:
//   - diskPath: The root path of the disk to scan for top-level directories.
//
// Returns:
//   - []string: A slice of directory paths from the specified disk.
//   - error: An error if the directory listing fails.
func GetTopLevelDirectories(diskPath string) ([]string, error) {
	var allDirs []string

	// Get all top-level directories on the specified disk
	dirs, err := GetDirectories(diskPath)
	if err != nil {
		return nil, err
	}

	// Filter out recycle bin directories and add to results
	for _, dir := range dirs {
		dirName := strings.ToLower(filepath.Base(dir))
		if dirName == "$recycle.bin" || dirName == "recycler" {
			continue
		}
		allDirs = append(allDirs, dir)
	}

	return allDirs, nil
}