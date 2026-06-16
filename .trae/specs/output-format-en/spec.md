# 英文输出格式标准化 - 产品需求文档

## Overview
- **Summary**: 将 Neptune 加密工具的所有输出改为纯英文文本格式，移除所有 emoji 图标，确保输出美观、清晰、可解析
- **Purpose**: 确保程序输出符合国际化标准，便于日志解析、自动化测试和跨平台兼容性
- **Target Users**: 所有使用 Neptune 的用户，特别是需要自动化集成和日志分析的企业用户

## Goals
- [ ] 移除所有打印函数中的 emoji 图标（, , , ℹ, ）
- [ ] 将所有中文输出改为英文输出
- [ ] 统一输出格式，使用简洁的前缀标识消息类型
- [ ] 确保输出换行美观，可读性强
- [ ] 编译最新版本并测试所有功能参数

## Non-Goals (Out of Scope)
- [ ] 改变程序的功能逻辑
- [ ] 添加新功能或参数
- [ ] 修改加密/解密算法
- [ ] 改变命令行参数结构

## Background & Context
- 当前打印函数使用 emoji 图标（, , , ℹ, ），在某些终端环境下可能显示异常
- 安全删除模块（secure_delete_*.go）包含中文输出，不符合国际化要求
- 用户需要纯文本输出便于日志分析和自动化测试

## Functional Requirements
- **FR-1**: 修改 PrintSuccess 函数 - 移除  图标，使用 "[SUCCESS]" 前缀
- **FR-2**: 修改 PrintError 函数 - 移除  图标，使用 "[ERROR]" 前缀
- **FR-3**: 修改 PrintWarning 函数 - 移除  图标，使用 "[WARNING]" 前缀
- **FR-4**: 修改 PrintInfo 函数 - 移除 ℹ 图标，使用 "[INFO]" 前缀
- **FR-5**: 修改 PrintQuestion 函数 - 移除  图标，使用 "[QUESTION]" 前缀
- **FR-6**: 将 secure_delete_windows.go 中的中文输出改为英文
- **FR-7**: 将 secure_delete_linux.go 中的中文输出改为英文
- **FR-8**: 将 secure_delete_darwin.go 中的中文输出改为英文

## Non-Functional Requirements
- **NFR-1**: 输出格式统一 - 所有消息使用相同的前缀格式 "[TYPE] message"
- **NFR-2**: 换行美观 - 每条消息单独一行，重要信息前后有空行分隔
- **NFR-3**: 可解析性 - 输出便于脚本解析和日志分析
- **NFR-4**: 兼容性 - 输出在所有终端环境中显示正常

## Constraints
- **Technical**: Go 语言，修改 utils.go 和安全删除模块文件
- **Business**: 保持向后兼容性，不改变功能逻辑
- **Dependencies**: 依赖 fmt 和 os 包

## Assumptions
- [ ] 用户期望英文输出
- [ ] 所有输出都通过 PrintInfo/PrintSuccess/PrintWarning/PrintError/PrintQuestion 函数输出
- [ ] 安全删除模块是唯一包含中文输出的模块

## Acceptance Criteria

### AC-1: 打印函数移除 emoji 图标
- **Given**: 调用任意打印函数（PrintInfo, PrintSuccess, PrintWarning, PrintError, PrintQuestion）
- **When**: 函数执行输出
- **Then**: 输出不包含任何 emoji 图标，使用文本前缀标识
- **Verification**: programmatic

### AC-2: 安全删除模块输出改为英文
- **Given**: 执行安全删除操作
- **When**: 程序运行在 Windows/Linux/macOS 平台
- **Then**: 所有输出消息为英文，格式统一
- **Verification**: human-judgment

### AC-3: 输出格式美观
- **Given**: 执行任意加密/解密操作
- **When**: 程序输出执行日志
- **Then**: 输出格式清晰，换行合理，便于阅读
- **Verification**: human-judgment

### AC-4: 编译和测试
- **Given**: 修改完成后
- **When**: 执行 go build 和功能测试
- **Then**: 编译成功，所有功能参数可用
- **Verification**: programmatic

## Open Questions
- [ ] 是否需要为不同日志级别添加颜色支持（可选）？
- [ ] 是否需要添加详细/简洁模式切换？