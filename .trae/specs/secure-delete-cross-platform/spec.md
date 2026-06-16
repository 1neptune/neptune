# 跨平台安全删除功能 - 产品需求文档

## Overview
- **Summary**: 为 Neptune 加密工具实现跨平台安全删除功能，支持 Windows、Linux、macOS 三大平台的数据删除和内存清除操作
- **Purpose**: 确保加密/解密操作后，敏感数据被彻底删除，防止通过系统恢复功能（如卷影副本、快照、TimeMachine）恢复，并确保敏感数据从内存中清除
- **Target Users**: 需要进行安全数据销毁的用户，包括企业用户和个人用户

## Goals
- [x] 实现 Windows 平台安全删除（删除 VSS 卷影副本、禁用启动修复、停用 VSS 服务、禁用系统还原、禁用 WinRE）
- [ ] 实现 Linux 平台安全删除（删除 LVM/btrfs/ZFS 快照、停止备份服务、禁用核心转储）
- [ ] 实现 macOS 平台安全删除（删除 TimeMachine 备份、停止 backupd 服务、清除本地快照、禁用 Spotlight）
- [x] 实现跨平台内存清除（SecureZeroMemory、SecureWipeString、SecureWipeSlice）
- [ ] 实现跨平台核心转储禁用
- [x] 实现权限检测（管理员/Root）
- [x] 实现详细执行信息输出

## Non-Goals (Out of Scope)
- [ ] 实现文件内容覆写（如 Gutmann 算法）- 仅删除文件和系统恢复数据
- [ ] 实现硬件级数据销毁
- [ ] 实现网络数据清除
- [ ] 实现第三方云备份清除

## Background & Context
- 当前代码库中 secure_delete_windows.go 已包含完整的 Windows 实现
- secure_delete.go 文件内容不完整（仅31字节），需要重写为跨平台接口
- Linux 和 macOS 模块尚未实现
- 项目已使用 --secure-remove-source 和 --remove-source 参数控制删除行为
- 内存清除已在 encrypt.go 和 decrypt.go 中部分实现

## Functional Requirements
- **FR-1**: 跨平台安全删除主入口函数 SecureDeleteFiles(files []string) - 根据操作系统调用对应模块
- **FR-2**: Windows 模块 - secureDeleteWindows(filePath string, isAdmin bool) - 删除 VSS 副本、禁用启动修复、停用 VSS 服务、禁用系统还原、禁用 WinRE 
- **FR-3**: Linux 模块 - secureDeleteLinux(filePath string, isAdmin bool) - 删除 LVM/btrfs/ZFS 快照、停止备份服务
- **FR-4**: macOS 模块 - secureDeleteMacOS(filePath string, isAdmin bool) - 删除 TimeMachine、停止 backupd、清除本地快照、禁用 Spotlight
- **FR-5**: 内存清除函数 - SecureZeroMemory(data []byte)、SecureWipeString(s *string)、SecureWipeSlice(slice interface{}) 
- **FR-6**: 核心转储禁用 - DisableCoreDump() - 跨平台实现
- **FR-7**: 权限检测 - IsAdmin() - 跨平台实现 
- **FR-8**: 系统级安全删除 - SecureDeleteSystem(volume string) - 批量执行系统级安全操作（使用 sync.Once 确保只执行一次）

## Non-Functional Requirements
- **NFR-1**: 执行信息输出 - 每个安全操作必须输出详细的执行日志（操作名称、状态、输出）
- **NFR-2**: 错误容忍 - 辅助清理步骤失败不应影响主流程
- **NFR-3**: 并发安全 - 内存清除操作使用 mutex 保护，系统级操作使用 sync.Once 确保只执行一次
- **NFR-4**: 编码处理 - Windows 命令行工具输出使用 GBK 编码，需转换为 UTF-8

## Constraints
- **Technical**: Go 语言，遵循现有代码风格和项目结构
- **Business**: 安全操作需要 Admin/Root 权限
- **Dependencies**: 依赖系统命令行工具（vssadmin、reagentc、bcdedit、lvremove、btrfs、zfs、tmutil 等）

## Assumptions
- [ ] 用户具有足够权限执行安全删除操作（Admin/Root）
- [ ] 系统命令行工具可用且版本兼容
- [ ] Linux 系统可能使用 LVM、btrfs 或 ZFS 文件系统
- [ ] macOS 系统已配置 TimeMachine 备份

## Acceptance Criteria

### AC-1: 跨平台安全删除主入口
- **Given**: 用户调用 utils.SecureDeleteFiles([]string{"test.txt"})
- **When**: 程序运行在 Windows/Linux/macOS 平台
- **Then**: 程序自动检测操作系统并调用对应平台的安全删除模块
- **Verification**: programmatic

### AC-2: Windows 安全删除功能 
- **Given**: 在 Windows 平台以管理员权限运行
- **When**: 执行安全删除操作
- **Then**: 成功删除 VSS 卷影副本、禁用启动修复、停用 VSS 服务、禁用系统还原、禁用 WinRE
- **Verification**: human-judgment（通过命令输出验证）

### AC-3: Linux 安全删除功能
- **Given**: 在 Linux 平台以 Root 权限运行
- **When**: 执行安全删除操作
- **Then**: 成功删除 LVM/btrfs/ZFS 快照、停止备份服务
- **Verification**: human-judgment（通过命令输出验证）

### AC-4: macOS 安全删除功能
- **Given**: 在 macOS 平台以 Root 权限运行
- **When**: 执行安全删除操作
- **Then**: 成功删除 TimeMachine 备份、停止 backupd、清除本地快照、禁用 Spotlight
- **Verification**: human-judgment（通过命令输出验证）

### AC-5: 内存清除功能 
- **Given**: 调用 SecureZeroMemory、SecureWipeString 函数
- **When**: 传入敏感数据（密钥、文件路径）
- **Then**: 数据被彻底清零，调用 untime.GC() 强制垃圾回收
- **Verification**: programmatic（通过测试验证数据已被清零）

### AC-6: 核心转储禁用
- **Given**: 调用 DisableCoreDump()
- **When**: 在任意平台执行
- **Then**: 核心转储功能被禁用
- **Verification**: human-judgment（通过系统配置验证）

### AC-7: 权限检测 
- **Given**: 调用 IsAdmin()
- **When**: 在不同权限下执行
- **Then**: 返回正确的权限状态（管理员/Root 返回 true，普通用户返回 false）
- **Verification**: programmatic

### AC-8: 系统级安全删除一次性执行
- **Given**: 批量处理多个文件并启用安全删除
- **When**: 对每个文件调用 SecureDeleteFiles
- **Then**: 系统级安全操作（如删除 VSS、禁用 WinRE）只执行一次
- **Verification**: programmatic（通过日志输出验证只执行一次）

## Open Questions
- [ ] Linux 平台是否需要支持特定发行版的备份服务？（如 systemd-timesyncd、rsnapshot 等）
- [ ] macOS 平台是否需要支持 APFS 快照？
