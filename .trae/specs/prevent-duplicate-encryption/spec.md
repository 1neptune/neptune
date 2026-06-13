# Neptune - 防止重复加密功能 Spec

## Overview
- **Summary**: 为 Neptune 加密程序添加重复加密检测功能，防止对已加密文件进行二次加密
- **Purpose**: 避免用户误操作导致数据损坏，提升用户体验和数据安全性
- **Target Users**: 使用 Neptune 进行文件加密的用户

## Goals
- 检测文件是否已加密（.ntp 格式）
- 在加密前验证文件格式，拒绝重复加密
- 提供清晰的错误提示信息
- 支持目录加密时批量检测

## Non-Goals (Out of Scope)
- 修改加密算法本身
- 添加文件解密验证功能（已在解密流程中处理）

## Background & Context
用户可能会误对已加密文件再次加密，导致数据无法正确解密。需要在加密流程开始前添加检测逻辑。

## Functional Requirements
- **FR-1**: 加密单个文件时，检测文件是否为 .ntp 格式（Neptune 加密格式）
- **FR-2**: 加密目录时，递归检测所有文件是否为 .ntp 格式
- **FR-3**: 检测到已加密文件时，拒绝加密并给出清晰的错误提示
- **FR-4**: 提供 `--force-override` 选项允许强制加密（覆盖现有加密文件）

## Non-Functional Requirements
- **NFR-1**: 检测逻辑必须快速，不影响整体加密性能
- **NFR-2**: 错误提示信息清晰易懂，指导用户正确操作
- **NFR-3**: 检测应该在实际加密操作之前进行

## Constraints
- **Technical**: 需要解析 Neptune 加密文件格式头部（1字节版本号 + 32字节公钥 + 16字节nonce）
- **Dependencies**: 依赖现有的文件处理逻辑

## Assumptions
- 加密文件都以 .ntp 扩展名结尾
- 文件头部包含特定的版本标识（0x01）

## Acceptance Criteria

### AC-1: 检测已加密文件
- **Given**: 用户尝试加密一个 .ntp 文件
- **When**: 执行 `neptune encrypt --input file.ntp --output ...`
- **Then**: 程序检测到文件已加密，输出错误信息并退出
- **Verification**: `programmatic`

### AC-2: 目录加密时跳过已加密文件
- **Given**: 用户尝试加密包含 .ntp 文件的目录
- **When**: 执行 `neptune encrypt --input dir/ --output ... --recursive`
- **Then**: 程序跳过 .ntp 文件，只加密未加密的文件
- **Verification**: `programmatic`

### AC-3: 强制覆盖选项
- **Given**: 用户明确指定 `--force-override` 选项
- **When**: 执行 `neptune encrypt --input file.ntp --output ... --force-override`
- **Then**: 程序允许对已加密文件进行二次加密
- **Verification**: `programmatic`

### AC-4: 错误提示信息
- **Given**: 用户尝试加密已加密文件
- **When**: 执行加密命令
- **Then**: 程序输出清晰的错误提示，说明文件已加密
- **Verification**: `human-judgment`

## Open Questions
- [ ] 是否需要支持自动检测非 .ntp 扩展名但实际已加密的文件？（通过文件头部检测）