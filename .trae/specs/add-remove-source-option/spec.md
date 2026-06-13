# Neptune - 删除源文件功能 Spec

## Why
用户在加密文件后希望自动删除原始文件，以确保敏感数据不会以明文形式残留。

## What Changes
- 在 `encrypt` 命令中添加 `--remove-source`（或 `-r`）选项
- 加密成功后，根据用户选项删除源文件
- 添加安全确认机制，防止误删

## Impact
- 修改 cmd/neptune/cmd/encrypt.go
- 影响加密流程

## ADDED Requirements

### Requirement: 删除源文件选项
系统应当提供删除源文件的选项。

#### Scenario: 加密并删除源文件
- **WHEN** 用户执行加密命令并指定 `--remove-source` 选项
- **AND** 加密成功完成
- **THEN** 系统删除源文件

#### Scenario: 删除前确认（交互式）
- **WHEN** 用户执行加密命令并指定 `--remove-source` 选项
- **AND** 未指定 `--force` 选项
- **THEN** 系统提示用户确认删除操作

## MODIFIED Requirements

### Requirement: 加密命令
加密命令应支持删除源文件选项。