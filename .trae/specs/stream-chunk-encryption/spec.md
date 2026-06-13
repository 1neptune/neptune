# 流式分块并行加密/解密 Spec

## Why
当前 Neptune 加密大文件时需要一次性加载整个文件到内存，导致内存占用过高（1GB 文件需要约 2GB 内存）。通过流式处理、分块并行和缓冲区复用，可以显著降低内存占用并提升加密速度。

## What Changes
- 添加流式加密/解密接口，支持分块读写
- 添加 `--chunk-size` 参数，允许用户自定义缓冲区大小
- 使用 `sync.Pool` 复用缓冲区，减少内存分配开销
- 支持多文件并行加密/解密（目录场景）
- 添加 `--parallel` 参数，控制并行处理数量

## Impact
- Affected specs: 无
- Affected code:
  - `pkg/crypto/crypto.go` - 添加流式加密/解密接口
  - `pkg/sosemanuk/sosemanuk.go` - 优化 XORKeyStream 性能
  - `cmd/neptune/cmd/encrypt.go` - 使用流式处理替代一次性加载
  - `cmd/neptune/cmd/decrypt.go` - 使用流式处理替代一次性加载
  - `internal/utils/utils.go` - 添加缓冲区池和并行处理工具

## ADDED Requirements

### Requirement: 流式加密/解密
系统 SHALL 提供流式加密/解密功能，支持分块读写大文件，避免一次性加载整个文件到内存。

#### Scenario: 加密大文件
- **WHEN** 用户加密一个 1GB 文件，使用默认 64KB 缓冲区
- **THEN** 内存占用不超过 64KB，加密完成后输出正确的加密文件

#### Scenario: 自定义缓冲区大小
- **WHEN** 用户使用 `--chunk-size 1MB` 参数加密文件
- **THEN** 系统使用 1MB 缓冲区进行流式加密

### Requirement: sync.Pool 缓冲区复用
系统 SHALL 使用 `sync.Pool` 复用加密/解密缓冲区，减少内存分配和 GC 压力。

#### Scenario: 多文件加密
- **WHEN** 用户加密目录下 100 个文件
- **THEN** 系统复用缓冲区，内存分配次数显著减少

### Requirement: 多文件并行处理
系统 SHALL 支持多文件并行加密/解密，利用多核 CPU 提升处理速度。

#### Scenario: 并行加密目录
- **WHEN** 用户使用 `--parallel 4` 参数加密目录
- **THEN** 系统同时处理 4 个文件，总处理时间减少约 60%

#### Scenario: 默认并行数
- **WHEN** 用户未指定 `--parallel` 参数
- **THEN** 系统使用单线程处理（保持向后兼容）

### Requirement: 命令行参数
系统 SHALL 提供以下新参数：

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--chunk-size` | string | "64KB" | 缓冲区大小，支持 KB/MB/GB 单位 |
| `--parallel` | int | 1 | 并行处理数量（仅目录场景有效） |

#### Scenario: 参数解析
- **WHEN** 用户指定 `--chunk-size 4MB`
- **THEN** 系统正确解析为 4 * 1024 * 1024 = 4194304 字节

#### Scenario: 无效参数
- **WHEN** 用户指定 `--chunk-size invalid`
- **THEN** 系统返回错误提示，说明支持的格式

## MODIFIED Requirements

### Requirement: 目录加密性能优化
原有目录加密使用串行处理，现改为支持并行处理。

**变更**：
- 新增 `--parallel` 参数控制并行数
- 默认保持串行处理（parallel=1）
- 使用 sync.Pool 复用缓冲区

### Requirement: 内存占用优化
原有加密需要 `文件大小 * 2` 内存，现改为固定缓冲区大小。

**变更**：
- 内存占用 = `chunk-size * parallel-count`
- 默认配置下内存占用约 64KB（单线程）或 256KB（4线程）