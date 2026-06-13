# Neptune - 远程资源下载功能调整 Spec

## Overview
- **Summary**: 修改 `--remote-url` 参数的行为，使其只下载远程资源到本地，不进行加密
- **Purpose**: 分离下载功能和加密功能，让用户可以先下载再决定是否加密
- **Target Users**: 需要下载远程资源但暂时不加密的用户

## Goals
- `--remote-url` 参数只下载文件到指定目录，不加密
- `--input` 参数仍然是加密的唯一目标
- 支持多个 `--remote-url` 批量下载

## Non-Goals (Out of Scope)
- 不改变现有的加密解密逻辑
- 不改变 `--input` 参数的行为

## Functional Requirements
- **FR-1**: `--remote-url` 参数只下载文件到 output 目录
- **FR-2**: `--remote-url` 下载的文件不进行加密
- **FR-3**: `--input` 参数仍然是加密的唯一目标
- **FR-4**: 支持多个 `--remote-url` 批量下载

## Acceptance Criteria

### AC-1: 远程资源下载
- **Given**: 用户使用 `--remote-url` 参数
- **When**: 执行 neptune encrypt --remote-url ... --output ...
- **Then**: 文件被下载到指定目录，不加密
- **Verification**: `programmatic`

### AC-2: 输入参数仍然是加密目标
- **Given**: 用户同时使用 `--input` 和 `--remote-url`
- **When**: 执行加密命令
- **Then**: `--input` 指定的文件被加密，`--remote-url` 指定的文件被下载
- **Verification**: `programmatic`

## Open Questions
- [ ] 是否需要添加独立的 download 命令？