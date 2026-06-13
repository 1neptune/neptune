# Neptune - 目录加密解密功能 Spec

## Why
用户需要加密整个目录及其子目录中的所有文件，而不仅仅是单个文件。

## What Changes
- 在 `encrypt` 和 `decrypt` 命令中添加 `--recursive`（或 `-R`）选项
- 支持递归加密/解密目录中的所有文件
- 保持目录结构，解密时重建目录结构
- 添加 `--include` 和 `--exclude` 选项支持文件过滤

## Impact
- 修改 cmd/neptune/cmd/encrypt.go 和 decrypt.go
- 添加目录处理工具函数
- 更新帮助文档

## ADDED Requirements

### Requirement: 目录加密
系统应当支持递归加密目录中的所有文件。

#### Scenario: 加密目录
- **WHEN** 用户执行加密命令并指定目录路径和 `--recursive` 选项
- **THEN** 系统递归加密目录中的所有文件，并保持目录结构

### Requirement: 目录解密
系统应当支持递归解密目录中的所有加密文件。

#### Scenario: 解密目录
- **WHEN** 用户执行解密命令并指定目录路径和 `--recursive` 选项
- **THEN** 系统递归解密目录中的所有加密文件，并重建原始目录结构

### Requirement: 文件过滤
系统应当支持包含/排除特定文件模式。

#### Scenario: 过滤文件
- **WHEN** 用户指定 `--include` 或 `--exclude` 选项
- **THEN** 系统只处理匹配的文件