# Neptune - 独立下载命令 Spec

## Overview
- **Summary**: 添加独立的 `download` 命令，用于从远程服务器下载文件
- **Purpose**: 分离下载功能和加密功能，让用户可以单独使用下载功能
- **Target Users**: 需要下载远程资源的用户

## Goals
- 添加独立的 `download` 命令
- 支持多个 `--remote-url` 参数批量下载
- 支持 `--output` 参数指定输出目录
- 从 `encrypt` 命令中移除 `--remote-url` 参数

## Non-Goals (Out of Scope)
- 不改变现有的加密解密逻辑

## Functional Requirements
- **FR-1**: 添加独立的 `download` 命令
- **FR-2**: `download` 命令支持 `--remote-url` 参数（可多次使用）
- **FR-3**: `download` 命令支持 `--output` 参数指定输出目录
- **FR-4**: 从 `encrypt` 命令中移除 `--remote-url` 参数

## Acceptance Criteria

### AC-1: 独立下载命令
- **Given**: 用户执行 `neptune download` 命令
- **When**: 使用 `--remote-url` 和 `--output` 参数
- **Then**: 文件被下载到指定目录
- **Verification**: `programmatic`

### AC-2: 批量下载
- **Given**: 用户提供多个 `--remote-url` 参数
- **When**: 执行下载命令
- **Then**: 所有文件都被下载到指定目录
- **Verification**: `programmatic`

## Open Questions
- [ ] 是否需要添加其他下载选项（如超时、代理等）？