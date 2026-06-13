# Neptune - 纯内存密钥加载 - 实现计划

## [x] Task 1: 在 curve25519 包中添加从字节数据加载密钥的函数
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 添加 `LoadKeyPairFromBytes()` 函数
  - 添加 `LoadPublicKeyFromBytes()` 函数
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: 能从字节数据加载密钥对
  - `programmatic` TR-1.2: 能从字节数据加载公钥
- **Notes**: 需要处理不同编码格式

## [ ] Task 2: 修改 utils 包添加 HTTP 下载到字节的函数
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 使用现有的 `DownloadBytes()` 函数
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-2.1: 能从 URL 下载数据到内存
- **Notes**: 已在之前的实现中完成

## [ ] Task 3: 修改 encrypt.go 支持纯内存密钥加载
- **Priority**: P0
- **Depends On**: Task 1, Task 2
- **Description**: 
  - 修改密钥加载逻辑，直接从 HTTP 响应加载到内存
  - 移除临时文件相关代码
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `programmatic` TR-3.1: 支持从 URL 纯内存加载私钥
  - `programmatic` TR-3.2: 支持从 URL 纯内存加载公钥
  - `programmatic` TR-3.3: --input 参数不接受 URL

## [ ] Task 4: 修改 decrypt.go 支持纯内存密钥加载
- **Priority**: P0
- **Depends On**: Task 1, Task 2
- **Description**: 
  - 修改密钥加载逻辑，直接从 HTTP 响应加载到内存
  - 移除临时文件相关代码
- **Acceptance Criteria Addressed**: AC-1, AC-3
- **Test Requirements**:
  - `programmatic` TR-4.1: 支持从 URL 纯内存加载私钥
  - `programmatic` TR-4.2: --input 参数不接受 URL

## [ ] Task 5: 添加 --remote-url 参数
- **Priority**: P1
- **Depends On**: Task 3
- **Description**: 
  - 添加 `--remote-url` 参数用于下载远程资源
- **Acceptance Criteria Addressed**: AC-4
- **Test Requirements**:
  - `programmatic` TR-5.1: 支持通过 --remote-url 下载并加密文件

## [ ] Task 6: 更新文档
- **Priority**: P2
- **Depends On**: All
- **Description**: 
  - 更新 README.md 说明新功能
- **Acceptance Criteria Addressed**: 所有
- **Test Requirements**:
  - `human-judgment` TR-6.1: 文档清晰说明新功能