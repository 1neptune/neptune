# encrypt/decrypt 命令进度显示增强 Spec

## Why
当前 encrypt 和 decrypt 命令在处理大文件和目录时，进度显示不够详细，用户无法了解：
1. 当前正在处理哪个文件
2. 单个文件的处理进度
3. 整体目录处理的进度

## What Changes
- 为 encrypt 命令的单文件加密添加实时进度显示
- 为 encrypt 命令的目录加密添加每个文件的进度显示
- 为 decrypt 命令的单文件解密添加实时进度显示（已实现）
- 为 decrypt 命令的目录解密添加每个文件的进度显示
- 统一进度显示格式

## Impact
- Affected specs: 无
- Affected code:
  - `cmd/neptune/cmd/encrypt.go` - 添加单文件和目录加密进度
  - `cmd/neptune/cmd/decrypt.go` - 添加目录解密进度

## ADDED Requirements

### Requirement: encrypt 单文件进度显示
系统 SHALL 在加密单个大文件时显示实时进度。

#### Scenario: 加密大文件
- **WHEN** 用户加密一个 1GB 的文件
- **THEN** 显示进度如 "加密进度: 45.2% (文件: video.mp4)"

### Requirement: encrypt 目录进度显示
系统 SHALL 在加密目录时显示每个文件的进度和整体进度。

#### Scenario: 加密目录
- **WHEN** 用户使用 `--recursive` 加密包含 10 个文件的目录
- **THEN** 显示如 "正在加密: file1.pdf [45.2%] | 进度: 3/10 (30.0%)"

### Requirement: decrypt 单文件进度显示
系统 SHALL 在解密单个大文件时显示实时进度（已实现）。

### Requirement: decrypt 目录进度显示
系统 SHALL 在解密目录时显示每个文件的进度和整体进度。

#### Scenario: 解密目录
- **WHEN** 用户使用 `--recursive` 解密包含 10 个文件的目录
- **THEN** 显示如 "正在解密: file1.ntp [45.2%] | 进度: 3/10 (30.0%)"

## 进度显示格式

| 场景 | 显示格式 | 示例 |
|------|---------|------|
| 单文件加密 | `加密进度: XX.X%` | `加密进度: 45.2%` |
| 单文件解密 | `解密进度: XX.X%` | `解密进度: 45.2%` |
| 目录加密 | `[文件名] [进度] | 总进度` | `[file1.pdf] [45%] | 3/10 (30%)` |
| 目录解密 | `[文件名] [进度] | 总进度` | `[file1.ntp] [45%] | 3/10 (30%)` |