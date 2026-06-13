# Neptune - 独立下载命令 - 任务列表

## [x] Task 1: 创建 download.go 命令文件
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 创建新的 download 命令
  - 支持 `--remote-url` 和 `--output` 参数
  - 支持批量下载多个 URL
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: download 命令可以下载单个文件
  - `programmatic` TR-1.2: download 命令可以批量下载多个文件

## [x] Task 2: 从 encrypt.go 中移除 --remote-url 参数
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 移除 encrypt 命令中的 `--remote-url` 参数
  - 更新 encrypt 命令的帮助文档
- **Acceptance Criteria Addressed**: FR-4
- **Test Requirements**:
  - `programmatic` TR-2.1: encrypt 命令不再支持 --remote-url 参数

## [x] Task 3: 更新 README.md 文档
- **Priority**: P1
- **Depends On**: Task 1
- **Description**: 更新 README.md 添加 download 命令说明
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `human-judgment` TR-3.1: 文档清晰说明 download 命令用法

## [x] Task 4: 编译测试
- **Priority**: P1
- **Depends On**: Task 1, Task 2
- **Description**: 编译 Windows 和 Linux 版本并测试功能
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-4.1: 编译成功 ✅
  - `programmatic` TR-4.2: download 命令正常工作