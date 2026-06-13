# Neptune - 远程加载功能 Spec

## Overview
- **Summary**: 为 Neptune 加密程序添加远程加载功能，支持通过 HTTP/HTTPS 加载密钥和资源文件
- **Purpose**: 方便用户从远程服务器获取密钥和资源，提高灵活性和安全性
- **Target Users**: 需要从远程服务器获取密钥或资源的用户

## Goals
- 支持通过 HTTP/HTTPS URL 加载私钥文件
- 支持通过 HTTP/HTTPS URL 加载公钥文件
- 支持通过 HTTP/HTTPS URL 下载资源文件（图片、文本等）
- 支持 URL 格式的输入路径（用于加密远程下载的文件）

## Non-Goals (Out of Scope)
- 不支持 FTP 或其他协议
- 不支持身份认证（如需认证，请使用其他工具下载后再使用）

## Background & Context
用户可能需要从远程服务器获取密钥或资源文件，例如从安全的密钥服务器获取密钥，或从 CDN 下载需要加密的文件。

## Functional Requirements
- **FR-1**: 支持 `--private-key` 参数接受 HTTP/HTTPS URL
- **FR-2**: 支持 `--public-key` 参数接受 HTTP/HTTPS URL
- **FR-3**: 支持 `--input` 参数接受 HTTP/HTTPS URL（下载并加密）
- **FR-4**: 支持 `--output` 参数接受 HTTP/HTTPS URL（暂不支持，输出始终为本地文件）

## Non-Functional Requirements
- **NFR-1**: 支持 HTTP 301/302 重定向
- **NFR-2**: 设置合理的超时时间（默认 30 秒）
- **NFR-3**: 提供清晰的错误提示

## Constraints
- **Technical**: 使用 Go 标准库的 net/http 包
- **Dependencies**: 需要处理网络请求和超时

## Assumptions
- 远程服务器支持标准 HTTP/HTTPS 协议
- 用户有访问远程资源的权限

## Acceptance Criteria

### AC-1: 远程加载私钥
- **Given**: 用户指定 HTTP/HTTPS URL 作为私钥路径
- **When**: 执行 `neptune encrypt --private-key https://example.com/private.key ...`
- **Then**: 程序从远程服务器下载私钥并使用
- **Verification**: `programmatic`

### AC-2: 远程加载公钥
- **Given**: 用户指定 HTTP/HTTPS URL 作为公钥路径
- **When**: 执行 `neptune encrypt --public-key https://example.com/public.key ...`
- **Then**: 程序从远程服务器下载公钥并使用
- **Verification**: `programmatic`

### AC-3: 远程加载输入文件
- **Given**: 用户指定 HTTP/HTTPS URL 作为输入文件
- **When**: 执行 `neptune encrypt --input https://example.com/file.txt ...`
- **Then**: 程序下载文件并加密
- **Verification**: `programmatic`

### AC-4: 错误处理
- **Given**: 远程资源不可访问
- **When**: 执行加密命令
- **Then**: 程序输出清晰的错误信息
- **Verification**: `human-judgment`

## Open Questions
- [ ] 是否需要支持自定义 HTTP 头？
- [ ] 是否需要支持代理服务器？