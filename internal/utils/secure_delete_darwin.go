//go:build darwin

package utils

import (
"os"
"strings"
)

func init() {
isAdminPlatform = func() bool { return os.Getuid() == 0 }
secureDeletePlatform = secureDeleteMacOS
secureDeleteSystemPlatform = secureDeleteMacOSSystem
disableCoreDumpPlatform = disableCoreDumpDarwin
}

func secureDeleteMacOS(filePath string, isAdmin bool) {
PrintInfo("[macOS] Starting secure delete operation...")

if isAdmin {
PrintInfo("[macOS] Deleting TimeMachine backups...")
deleteTimeMachine()

PrintInfo("[macOS] Stopping backupd service...")
stopBackupdService()

PrintInfo("[macOS] Clearing local snapshots...")
clearLocalSnapshots()

PrintInfo("[macOS] Disabling Spotlight indexing...")
disableSpotlight()
} else {
PrintWarning("[macOS] Not running as root, skipping root-only operations")
}
}

func secureDeleteMacOSSystem(volume string, isAdmin bool) {
	if isAdmin {
		PrintInfo("[macOS] Executing system-level secure delete...")

		deleteTimeMachine()
		stopBackupdService()
		clearLocalSnapshots()
		disableSpotlight()
	}
}

func deleteTimeMachine() {
cmds := []struct {
name string
cmd  string
args []string
}{
{"Stop TimeMachine", "tmutil", []string{"stopbackup"}},
{"Disable TimeMachine auto backup", "tmutil", []string{"disable"}},
{"Delete all TimeMachine backups", "tmutil", []string{"delete", "-all"}},
}

for _, c := range cmds {
PrintInfo("[macOS] Executing: %s", c.name)
output, err := executeCommand(c.name, c.cmd, c.args)
if err != nil {
PrintWarning("[macOS] %s failed: %v", c.name, err)
if len(output) > 0 {
PrintInfo("[macOS] Command output: %s", output)
}
} else {
PrintSuccess("[macOS] %s succeeded", c.name)
if len(output) > 0 {
PrintInfo("[macOS] Command output: %s", output)
}
}
}
}

func stopBackupdService() {
cmds := []struct {
name string
cmd  string
args []string
}{
{"Stop backupd service", "launchctl", []string{"stop", "com.apple.backupd"}},
{"Disable backupd service", "launchctl", []string{"disable", "com.apple.backupd"}},
}

for _, c := range cmds {
PrintInfo("[macOS] Executing: %s", c.name)
output, err := executeCommand(c.name, c.cmd, c.args)
if err != nil {
PrintWarning("[macOS] %s failed: %v", c.name, err)
if len(output) > 0 {
PrintInfo("[macOS] Command output: %s", output)
}
} else {
PrintSuccess("[macOS] %s succeeded", c.name)
}
}
}

func clearLocalSnapshots() {
output, err := executeCommand("List local snapshots", "tmutil", []string{"listlocalsnapshots", "/"})
if err != nil {
PrintWarning("[macOS] Failed to list local snapshots: %v", err)
return
}

if len(output) > 0 {
lines := strings.Split(strings.TrimSpace(output), "\n")
for _, line := range lines {
if strings.Contains(line, "com.apple.TimeMachine") {
snapshotName := strings.TrimSpace(line)
PrintInfo("[macOS] Found local snapshot: %s", snapshotName)
executeCommand("Delete local snapshot "+snapshotName, "tmutil", []string{"deletelocalsnapshots", snapshotName})
}
}
}
}

func disableSpotlight() {
cmds := []struct {
name string
cmd  string
args []string
}{
{"Disable Spotlight indexing", "mdutil", []string{"-a", "-i", "off"}},
{"Clear Spotlight index", "mdutil", []string{"-a", "-E"}},
}

for _, c := range cmds {
PrintInfo("[macOS] Executing: %s", c.name)
output, err := executeCommand(c.name, c.cmd, c.args)
if err != nil {
PrintWarning("[macOS] %s failed: %v", c.name, err)
if len(output) > 0 {
PrintInfo("[macOS] Command output: %s", output)
}
} else {
PrintSuccess("[macOS] %s succeeded", c.name)
if len(output) > 0 {
PrintInfo("[macOS] Command output: %s", output)
}
}
}
}

func disableCoreDumpDarwin() {
cmds := []struct {
name string
cmd  string
args []string
}{
{"Disable core file generation", "launchctl", []string{"limit", "core", "0", "0"}},
{"Set sysctl parameter", "sysctl", []string{"-w", "kern.corefile="}},
}

for _, c := range cmds {
PrintInfo("[macOS] Executing: %s", c.name)
output, err := executeCommand(c.name, c.cmd, c.args)
if err != nil {
PrintWarning("[macOS] %s failed: %v", c.name, err)
if len(output) > 0 {
PrintInfo("[macOS] Command output: %s", output)
}
} else {
PrintSuccess("[macOS] %s succeeded", c.name)
}
}
}