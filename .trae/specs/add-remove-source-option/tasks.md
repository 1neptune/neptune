# Tasks

- [x] Task 1: 修改 encrypt 命令，添加 --remove-source 选项
  - [x] SubTask 1.1: 在 encrypt.go 中添加 -r/--remove-source 标志
  - [x] SubTask 1.2: 实现删除源文件的逻辑
  - [x] SubTask 1.3: 添加确认机制（非强制模式下提示用户）
  - [x] SubTask 1.4: 更新帮助文档

- [x] Task 2: 更新测试
  - [x] SubTask 2.1: 添加删除源文件的测试用例
  - [x] SubTask 2.2: 测试确认机制

- [x] Task 3: 更新 README 文档
  - [x] SubTask 3.1: 添加 --remove-source 选项说明

# Task Dependencies
- [Task 1] 依赖于已完成的加密功能
- [Task 2] 依赖于 [Task 1]
- [Task 3] 依赖于 [Task 1]