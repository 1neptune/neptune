# Neptune - 远程加载功能 - 实现计划

## [x] Task 1: 添加 HTTP 下载工具函数
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 在 `internal/utils/utils.go` 中添加 HTTP/HTTPS 下载函数
  - 支持超时设置和重定向处理
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `programmatic` TR-1.1: 能成功下载 HTTP 资源
  - `programmatic` TR-1.2: 能成功下载 HTTPS 资源
  - `programmatic` TR-1.3: 超时能正确处理
- **Notes**: 需要处理网络错误和超时

## [x] Task 2: 添加 URL 检测函数
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 添加检测字符串是否为 HTTP/HTTPS URL 的函数
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `programmatic` TR-2.1: 正确识别 HTTP URL
  - `programmatic` TR-2.2: 正确识别 HTTPS URL
  - `programmatic` TR-2.3: 正确识别本地路径
- **Notes**: 使用标准库的 net/url 包

## [x] Task 3: 修改密钥加载逻辑
- **Priority**: P0
- **Depends On**: Task 1, Task 2
- **Description**: 
  - 修改 `cmd/encrypt.go` 和 `cmd/decrypt.go` 支持从 URL 加载密钥
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-3.1: 支持从 URL 加载私钥
  - `programmatic` TR-3.2: 支持从 URL 加载公钥
- **Notes**: 需要修改密钥加载函数

## [ ] Task 4: 修改输入文件加载逻辑
- **Priority**: P0
- **Depends On**: Task 1, Task 2
- **Description**: 
  - 修改 `cmd/encrypt.go` 支持从 URL 下载输入文件
- **Acceptance Criteria Addressed**: AC-3
- **Test Requirements**:
  - `programmatic` TR-4.1: 支持从 URL 下载并加密文件
- **Notes**: 需要临时保存下载的文件

## [ ] Task 5: 添加超时配置选项
- **Priority**: P1
- **Depends On**: Task 1
- **Description**: 
  - 添加 `--timeout` 参数配置 HTTP 请求超时
- **Acceptance Criteria Addressed**: NFR-2
- **Test Requirements**:
  - `programmatic` TR-5.1: 超时参数能正确设置
- **Notes**: 默认超时 30 秒

## [ ] Task 6: 更新文档
- **Priority**: P2
- **Depends On**: All
- **Description**: 
  - 更新 README.md 说明远程加载功能
- **Acceptance Criteria Addressed**: AC-4
- **Test Requirements**:
  - `human-judgment` TR-6.1: 文档清晰说明新功能