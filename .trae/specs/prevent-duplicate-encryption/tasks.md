# Neptune - 防止重复加密功能 - 实现计划

## [x] Task 1: 添加文件格式检测函数
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 在 `internal/utils/utils.go` 中添加检测文件是否为 Neptune 加密格式的函数
  - 检测逻辑：检查文件扩展名是否为 .ntp，或检查文件头部是否包含 Neptune 格式标识
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: 检测 .ntp 文件返回 true
  - `programmatic` TR-1.2: 检测非 .ntp 文件返回 false
- **Notes**: 需要处理文件不存在或无法读取的情况

## [x] Task 2: 修改加密命令添加重复加密检测
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 修改 `cmd/encrypt.go` 添加重复加密检测逻辑
  - 在加密前检查目标文件是否已加密
  - 添加 `--force-override` 选项允许强制加密
- **Acceptance Criteria Addressed**: AC-1, AC-3, AC-4
- **Test Requirements**:
  - `programmatic` TR-2.1: 加密 .ntp 文件时拒绝并输出错误
  - `programmatic` TR-2.2: 使用 --force-override 选项时允许加密
  - `human-judgment` TR-2.3: 错误提示信息清晰易懂
- **Notes**: 需要添加新的命令行参数

## [x] Task 3: 修改目录加密逻辑
- **Priority**: P0
- **Depends On**: Task 2
- **Description**: 
  - 修改目录加密逻辑，跳过已加密的 .ntp 文件
  - 添加跳过文件的日志输出
- **Acceptance Criteria Addressed**: AC-2, AC-4
- **Test Requirements**:
  - `programmatic` TR-3.1: 目录加密时跳过 .ntp 文件
  - `human-judgment` TR-3.2: 输出跳过的文件列表
- **Notes**: 需要保持原有的 include/exclude 过滤逻辑

## [ ] Task 4: 添加单元测试
- **Priority**: P1
- **Depends On**: Task 1, Task 2, Task 3
- **Description**: 
  - 为新添加的函数编写单元测试
  - 测试各种边界情况
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `programmatic` TR-4.1: 所有测试用例通过
- **Notes**: 测试应覆盖正常和异常情况

## [ ] Task 5: 更新 README.md
- **Priority**: P2
- **Depends On**: Task 2
- **Description**: 
  - 更新文档说明新的 `--force-override` 选项
  - 添加重复加密检测功能的说明
- **Acceptance Criteria Addressed**: AC-4
- **Test Requirements**:
  - `human-judgment` TR-5.1: 文档清晰说明新功能
- **Notes**: 文档更新应简洁明了