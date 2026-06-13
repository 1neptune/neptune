# Neptune - 纯内存密钥加载与输入参数规范

## Overview
- **Summary**: 修改 Neptune 加密程序，支持密钥对纯内存加载，取消临时文件方式，限制 `--input` 参数只能用于本地文件
- **Purpose**: 提高安全性，密钥完全不落地；明确参数职责，避免混淆
- **Target Users**: 需要更高安全性的用户

## Goals
- 取消临时文件方式加载密钥对
- 支持密钥对从 HTTP/HTTPS URL 纯内存加载
- `--input` 参数仅支持本地文件路径，不支持 URL
- 添加独立参数用于远程资源下载

## Non-Goals (Out of Scope)
- 不改变现有的本地密钥文件加载方式
- 不改变加密/解密算法

## Background & Context
用户希望提高安全性，密钥从远程加载时完全在内存中处理，不写入临时文件。同时希望明确区分本地输入和远程输入。

## Functional Requirements
- **FR-1**: 支持从 HTTP/HTTPS URL 纯内存加载私钥
- **FR-2**: 支持从 HTTP/HTTPS URL 纯内存加载公钥
- **FR-3**: `--input` 参数仅接受本地文件路径
- **FR-4**: 添加 `--remote-url` 参数用于下载远程资源
- **FR-5**: 移除 `--input` 参数对 URL 的支持

## Non-Functional Requirements
- **NFR-1**: 密钥在内存中处理，不写入磁盘
- **NFR-2**: 提供清晰的错误提示

## Constraints
- **Technical**: 使用 Go 的 io.Reader 直接从 HTTP 响应加载密钥

## Assumptions
- 用户理解内存加载的安全性优势
- 用户有访问远程密钥服务器的权限

## Acceptance Criteria

### AC-1: 纯内存加载私钥
- **Given**: 用户指定 HTTP/HTTPS URL 作为私钥路径
- **When**: 执行加密/解密命令
- **Then**: 密钥从远程下载到内存，不写入临时文件
- **Verification**: `programmatic`

### AC-2: 纯内存加载公钥
- **Given**: 用户指定 HTTP/HTTPS URL 作为公钥路径
- **When**: 执行加密命令
- **Then**: 密钥从远程下载到内存，不写入临时文件
- **Verification**: `programmatic`

### AC-3: --input 仅支持本地文件
- **Given**: 用户在 `--input` 参数中指定 URL
- **When**: 执行命令
- **Then**: 程序报错提示使用正确参数
- **Verification**: `programmatic`

### AC-4: 远程资源下载
- **Given**: 用户使用 `--remote-url` 参数
- **When**: 执行加密命令
- **Then**: 远程文件下载到内存并加密
- **Verification**: `programmatic`

## Open Questions
- [ ] 是否需要支持远程资源解密？