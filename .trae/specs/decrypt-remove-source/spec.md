# 解密后删除加密文件功能 Spec

## Why
用户希望在解密完成后自动删除原始的加密文件（.ntp 文件），与 encrypt 命令的 `--remove-source` 功能对称。

## What Changes
- 在 decrypt 命令中添加 `--remove-source` 参数
- 修改 `decryptSingleFile` 函数，支持解密后删除源文件
- 修改 `decryptDirectory` 函数，支持并行解密后删除源文件
- 需要先关闭文件再删除（Windows 限制）

## Impact
- Affected specs: 无
- Affected code:
  - `cmd/neptune/cmd/decrypt.go` - 添加参数和删除逻辑

## ADDED Requirements

### Requirement: 解密后删除源文件
系统 SHALL 在解密完成后删除原始加密文件（.ntp 文件）。

#### Scenario: 解密单个文件并删除源文件
- **WHEN** 用户使用 `--remove-source` 参数解密文件
- **THEN** 解密成功后自动删除原始加密文件

#### Scenario: 解密目录并删除源文件
- **WHEN** 用户使用 `--remove-source` 参数解密目录
- **THEN** 每个文件解密成功后自动删除对应的加密文件

#### Scenario: 并行解密并删除源文件
- **WHEN** 用户使用 `--parallel` 和 `--remove-source` 参数
- **THEN** 解密成功后先关闭文件再删除，避免 Windows 文件锁定问题