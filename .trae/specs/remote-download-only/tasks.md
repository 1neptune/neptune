# Neptune - 远程资源下载功能调整 - 任务列表

## [x] Task 1: 修改 encrypt.go 中 --remote-url 的处理逻辑
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 修改 `encryptRemoteURL` 的处理逻辑，使其只下载文件而不加密
  - 添加下载完成后的提示信息
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: 使用 `--remote-url` 下载文件后，文件不应是加密格式（.ntp）
  - `programmatic` TR-1.2: 使用 `--input` 和 `--remote-url` 时，只有 `--input` 的文件被加密

## [x] Task 2: 更新 README.md 文档
- **Priority**: P1
- **Depends On**: Task 1
- **Description**: 更新 README.md 中关于 `--remote-url` 的说明
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `human-judgment` TR-2.1: 文档清晰说明 `--remote-url` 只下载不加密

## [x] Task 3: 编译测试
- **Priority**: P1
- **Depends On**: Task 1
- **Description**: 编译 Windows 和 Linux 版本并测试功能
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-3.1: 编译成功 ✅
  - `programmatic` TR-3.2: 下载功能正常工作