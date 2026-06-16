# 跨平台安全删除功能 - 实现计划

## [x] Task 1: 重写 secure_delete.go 跨平台主接口
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 重写 secure_delete.go 文件，实现跨平台安全删除主入口函数
  - 包含 SecureDeleteFiles(files []string) - 根据操作系统调用对应模块
  - 包含 SecureDeleteSystem(volume string) - 系统级安全删除（使用 sync.Once）
  - 包含内存清除函数 SecureZeroMemory、SecureWipeString、SecureWipeSlice
  - 包含跨平台核心转储禁用 DisableCoreDump()
  - 包含权限检测 IsAdmin()（调用平台特定实现）
  - 包含 executeCommand 函数和 gbkToUtf8 编码转换函数
- **Acceptance Criteria Addressed**: AC-1, AC-5, AC-6, AC-7, AC-8
- **Test Requirements**:
  - programmatic TR-1.1: 验证 SecureDeleteFiles 在不同 OS 下调用对应平台模块 ✓
  - programmatic TR-1.2: 验证 SecureZeroMemory 能正确清零字节切片 ✓
  - programmatic TR-1.3: 验证 SecureWipeString 能正确清除字符串 ✓
  - programmatic TR-1.4: 验证 SecureDeleteSystem 使用 sync.Once 确保只执行一次 ✓
  - human-judgement TR-1.5: 代码结构清晰，符合项目规范 ✓

## [x] Task 2: 更新 secure_delete_windows.go Windows 模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 更新 secure_delete_windows.go，添加 isWindowsAdmin()、disableCoreDumpWindows() 函数
  - 确保与 secure_delete.go 中的接口正确对接
  - 添加详细的执行日志输出
  - 确保 GBK 编码转换正确处理
- **Acceptance Criteria Addressed**: AC-2, AC-6, AC-7
- **Test Requirements**:
  - human-judgement TR-2.1: Windows 模块函数与主接口正确对接 ✓
  - human-judgement TR-2.2: 命令执行输出包含详细日志 ✓
  - human-judgement TR-2.3: GBK 编码转换正确处理中文输出 ✓

## [x] Task 3: 创建 secure_delete_linux.go Linux 模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 创建 secure_delete_linux.go 文件，使用 //go:build linux 构建标签
  - 实现 isLinuxRoot() 函数检测 Root 权限
  - 实现 secureDeleteLinux(filePath string, isAdmin bool) 函数
  - 实现 deleteLVMSnapshots() 删除 LVM 快照
  - 实现 deleteBtrfsSnapshots() 删除 btrfs 快照
  - 实现 deleteZFSSnapshots() 删除 ZFS 快照
  - 实现 stopBackupServices() 停止备份服务
  - 实现 disableCoreDumpLinux() 禁用核心转储
  - 添加详细执行日志输出
- **Acceptance Criteria Addressed**: AC-3, AC-6, AC-7
- **Test Requirements**:
  - human-judgement TR-3.1: Linux 模块实现完整，包含所有安全删除功能 ✓
  - human-judgement TR-3.2: 命令执行输出包含详细日志 ✓
  - human-judgement TR-3.3: 错误处理完善，失败不影响主流程 ✓

## [x] Task 4: 创建 secure_delete_darwin.go macOS 模块
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 创建 secure_delete_darwin.go 文件，使用 //go:build darwin 构建标签
  - 实现 isMacOSRoot() 函数检测 Root 权限
  - 实现 secureDeleteMacOS(filePath string, isAdmin bool) 函数
  - 实现 deleteTimeMachine() 删除 TimeMachine 备份
  - 实现 stopBackupdService() 停止 backupd 服务
  - 实现 clearLocalSnapshots() 清除本地快照
  - 实现 disableSpotlight() 禁用 Spotlight 索引
  - 实现 disableCoreDumpDarwin() 禁用核心转储
  - 添加详细执行日志输出
- **Acceptance Criteria Addressed**: AC-4, AC-6, AC-7
- **Test Requirements**:
  - human-judgement TR-4.1: macOS 模块实现完整，包含所有安全删除功能 ✓
  - human-judgement TR-4.2: 命令执行输出包含详细日志 ✓
  - human-judgement TR-4.3: 错误处理完善，失败不影响主流程 ✓

## [x] Task 5: 验证跨平台编译和测试
- **Priority**: P1
- **Depends On**: Task 1, Task 2, Task 3, Task 4
- **Description**: 
  - 验证 Windows 平台编译成功
  - 验证 Linux 平台编译成功（使用交叉编译）
  - 验证 macOS 平台编译成功（使用交叉编译）
  - 运行测试文件验证功能
- **Acceptance Criteria Addressed**: AC-1
- **Test Requirements**:
  - programmatic TR-5.1: Windows 平台编译成功（go build -o neptune.exe）✓
  - programmatic TR-5.2: Linux 平台交叉编译成功（GOOS=linux GOARCH=amd64 go build）✓
  - programmatic TR-5.3: macOS 平台交叉编译成功（GOOS=darwin GOARCH=amd64 go build）✓
  - human-judgement TR-5.4: 测试输出显示正确的平台检测和模块调用 ✓
