# Neptune - 安全删除功能 - 产品需求文档

## Overview
- **Summary**: 在加密/解密操作完成后，根据操作系统类型自动执行全面的安全清理操作，包括检测权限、删除卷影副本、禁用系统恢复功能等，防止敏感数据被恢复，并输出详细执行信息。
- **Purpose**: 增强数据安全性，确保删除的文件无法通过系统恢复功能被还原，提供完整的安全删除流程。
- **Target Users**: 需要高度安全的数据处理场景，如机密文件处理、安全清理等。

## Goals
- 检测当前操作系统类型（Windows/Linux/macOS）
- 检测当前用户权限（Admin/Root）
- Windows: 删除指定卷的VSS副本、禁用启动修复、停用VSS服务、禁用系统还原、禁用WinRE
- Linux: 删除LVM快照、删除btrfs快照、删除ZFS快照、停止备份服务
- macOS: 删除TimeMachine备份、停止backupd、清除本地快照、禁用Spotlight
- 输出详细执行信息
- 支持跨平台自适应处理

## Non-Goals (Out of Scope)
- 实现完整的数据粉碎功能
- 修改系统级安全策略
- 处理第三方备份工具

## Background & Context
- 操作系统通常会创建文件的卷影副本或恢复点，即使文件被删除，仍可能通过这些机制恢复
- 对于敏感数据处理场景，需要确保文件被彻底删除，无法恢复
- 当前项目已支持 `--remove-source` 参数删除源文件，但缺少防止恢复的机制

## Functional Requirements
- **FR-1**: 检测当前操作系统类型（Windows/macOS/Linux）
- **FR-2**: 检测当前用户是否具有管理员/root权限
- **FR-3**: Windows模块：删除指定卷的VSS副本
- **FR-4**: Windows模块：禁用启动修复
- **FR-5**: Windows模块：停用VSS服务
- **FR-6**: Windows模块：禁用系统还原
- **FR-7**: Windows模块：禁用WinRE
- **FR-8**: Linux模块：删除LVM快照
- **FR-9**: Linux模块：删除btrfs快照
- **FR-10**: Linux模块：删除ZFS快照
- **FR-11**: Linux模块：停止备份服务
- **FR-12**: macOS模块：删除TimeMachine备份
- **FR-13**: macOS模块：停止backupd服务
- **FR-14**: macOS模块：清除本地快照
- **FR-15**: macOS模块：禁用Spotlight
- **FR-16**: 输出详细执行信息
- **FR-17**: 操作失败时记录警告但不中断主流程

## Non-Functional Requirements
- **NFR-1**: 跨平台兼容性，支持Windows、macOS、Linux
- **NFR-2**: 操作失败时不影响主流程（加密/解密操作）
- **NFR-3**: 需要管理员权限时给出明确提示
- **NFR-4**: 输出详细的执行日志

## Constraints
- **Technical**: 不同操作系统的卷影副本和恢复机制不同，需要平台特定实现
- **Dependencies**: Windows需要vssadmin、bcdedit命令；macOS需要tmutil命令；Linux需要btrfs、zfs命令

## Assumptions
- 用户可能需要管理员权限才能执行某些操作
- 系统工具在目标系统上可用

## Acceptance Criteria

### AC-1: 操作系统检测
- **Given**: 执行安全删除操作
- **When**: 检测操作系统类型
- **Then**: 正确识别Windows/Linux/macOS
- **Verification**: `programmatic`

### AC-2: 权限检测
- **Given**: 执行安全删除操作
- **When**: 检测用户权限
- **Then**: 正确识别Admin/Root权限
- **Verification**: `programmatic`

### AC-3: Windows VSS删除
- **Given**: Windows系统且有管理员权限
- **When**: 删除源文件后
- **Then**: 删除指定卷的VSS副本
- **Verification**: `programmatic`

### AC-4: Windows禁用启动修复
- **Given**: Windows系统且有管理员权限
- **When**: 执行安全删除操作
- **Then**: 禁用启动修复功能
- **Verification**: `programmatic`

### AC-5: Windows停用VSS服务
- **Given**: Windows系统且有管理员权限
- **When**: 执行安全删除操作
- **Then**: 停用VSS服务
- **Verification**: `programmatic`

### AC-6: Windows禁用系统还原
- **Given**: Windows系统且有管理员权限
- **When**: 执行安全删除操作
- **Then**: 禁用系统还原
- **Verification**: `programmatic`

### AC-7: Windows禁用WinRE
- **Given**: Windows系统且有管理员权限
- **When**: 执行安全删除操作
- **Then**: 禁用WinRE
- **Verification**: `programmatic`

### AC-8: Linux删除快照
- **Given**: Linux系统且有root权限
- **When**: 删除源文件后
- **Then**: 删除LVM/btrfs/ZFS快照
- **Verification**: `programmatic`

### AC-9: Linux停止备份服务
- **Given**: Linux系统且有root权限
- **When**: 执行安全删除操作
- **Then**: 停止备份服务
- **Verification**: `programmatic`

### AC-10: macOS删除TimeMachine
- **Given**: macOS系统
- **When**: 删除源文件后
- **Then**: 删除TimeMachine备份
- **Verification**: `programmatic`

### AC-11: macOS停止backupd
- **Given**: macOS系统
- **When**: 执行安全删除操作
- **Then**: 停止backupd服务
- **Verification**: `programmatic`

### AC-12: macOS清除本地快照
- **Given**: macOS系统
- **When**: 执行安全删除操作
- **Then**: 清除本地快照
- **Verification**: `programmatic`

### AC-13: macOS禁用Spotlight
- **Given**: macOS系统
- **When**: 执行安全删除操作
- **Then**: 禁用Spotlight索引
- **Verification**: `programmatic`

### AC-14: 详细执行信息输出
- **Given**: 执行安全删除操作
- **When**: 执行各模块操作
- **Then**: 输出详细执行信息
- **Verification**: `human-judgment`

### AC-15: 错误处理
- **Given**: 安全删除操作失败（如权限不足）
- **When**: 执行安全删除操作
- **Then**: 记录警告信息但不中断主流程
- **Verification**: `human-judgment`

## Open Questions
- [ ] 是否需要支持恢复被禁用的系统恢复功能？