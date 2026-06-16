package utils

import (
"bytes"
"io"
"os/exec"
"runtime"
"sync"

"golang.org/x/text/encoding/simplifiedchinese"
"golang.org/x/text/transform"
)

var (
	memoryCleanupMu  sync.Mutex
	secureDeleteOnce sync.Once

	secureDeletePlatform      func(filePath string, isAdmin bool)
	secureDeleteSystemPlatform func(volume string, isAdmin bool)
	disableCoreDumpPlatform   func()
	isAdminPlatform           func() bool
)

type OSType int

const (
OSUnknown OSType = iota
OSWindows
OSLinux
OSMacOS
)

func GetOS() OSType {
switch runtime.GOOS {
case "windows":
return OSWindows
case "linux":
return OSLinux
case "darwin":
return OSMacOS
default:
return OSUnknown
}
}

func IsAdmin() bool {
if isAdminPlatform != nil {
return isAdminPlatform()
}
return false
}

func SecureDeleteFiles(files []string) {
	isAdmin := IsAdmin()

	if !isAdmin {
		PrintInfo("[Security] Secure delete skipped: requires Admin/Root privileges")
		return
	}

	PrintInfo("[Security] Starting secure delete operation...")

	osType := GetOS()
	osName := map[OSType]string{
		OSWindows: "Windows",
		OSLinux:   "Linux",
		OSMacOS:   "macOS",
		OSUnknown: "Unknown",
	}[osType]
	PrintInfo("[Security] Operating system: %s", osName)
	PrintInfo("[Security] Permission check: Admin/Root")

	var volume string
	if len(files) > 0 {
		volume = getVolumeFromPath(files[0])
		PrintInfo("[Security] Target volume: %s", volume)

		if secureDeletePlatform != nil {
			secureDeletePlatform(files[0], isAdmin)
		} else {
			PrintWarning("[Security] Unsupported operating system, skipping secure delete")
		}
	}

	SecureDeleteSystem(volume)
}

func SecureDeleteSystem(volume string) {
	secureDeleteOnce.Do(func() {
		PrintInfo("[Security] Executing system-level secure delete...")

		isAdmin := IsAdmin()

		if secureDeleteSystemPlatform != nil {
			secureDeleteSystemPlatform(volume, isAdmin)
		}

		DisableCoreDump()
	})
}

func DisableCoreDump() {
PrintInfo("[Security] Disabling core dump...")

if disableCoreDumpPlatform != nil {
disableCoreDumpPlatform()
} else {
PrintInfo("[Security] Core dump disabling not supported on this platform")
}
}

func SecureZeroMemory(data []byte) {
memoryCleanupMu.Lock()
defer memoryCleanupMu.Unlock()

if len(data) == 0 {
return
}

for i := range data {
data[i] = 0
}

runtime.GC()
}

func SecureWipeString(s *string) {
if s == nil || *s == "" {
return
}

memoryCleanupMu.Lock()
defer memoryCleanupMu.Unlock()

runes := []rune(*s)
for i := range runes {
runes[i] = 0
}
*s = ""

runtime.GC()
}

func SecureWipeSlice(slice interface{}) {
memoryCleanupMu.Lock()
defer memoryCleanupMu.Unlock()

switch v := slice.(type) {
case []byte:
for i := range v {
v[i] = 0
}
case []string:
for i := range v {
SecureWipeString(&v[i])
}
case []interface{}:
for i := range v {
SecureWipeSlice(v[i])
}
}

runtime.GC()
}

func executeCommand(description, cmd string, args []string) (string, error) {
PrintInfo("[Command] Executing: %s", description)
PrintInfo("[Command] Command: %s %v", cmd, args)

var output []byte
var err error

command := exec.Command(cmd, args...)
var stdout, stderr bytes.Buffer
command.Stdout = &stdout
command.Stderr = &stderr

err = command.Run()
output = stdout.Bytes()
if len(output) == 0 {
output = stderr.Bytes()
}

var outputStr string
if runtime.GOOS == "windows" {
outputStr = gbkToUtf8(string(output))
} else {
outputStr = string(output)
}

if err != nil {
PrintWarning("[Command] %s failed: %v", description, err)
if len(outputStr) > 0 {
PrintInfo("[Command] Output: %s", outputStr)
}
} else {
PrintSuccess("[Command] %s succeeded", description)
if len(outputStr) > 0 {
PrintInfo("[Command] Output: %s", outputStr)
}
}

if len(output) > 0 {
SecureZeroMemory(output)
}

return outputStr, err
}

func gbkToUtf8(s string) string {
reader := transform.NewReader(bytes.NewReader([]byte(s)), simplifiedchinese.GBK.NewDecoder())
decoded, err := io.ReadAll(reader)
if err != nil {
return s
}
return string(decoded)
}

func getVolumeFromPath(filePath string) string {
switch runtime.GOOS {
case "windows":
if len(filePath) >= 2 && filePath[1] == ':' {
return filePath[:2]
}
return "C:"
default:
return "/"
}
}
