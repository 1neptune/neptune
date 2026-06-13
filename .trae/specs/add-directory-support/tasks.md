# Tasks

- [x] Task 1: 在 encrypt 命令中添加目录支持
  - [x] SubTask 1.1: 添加 --recursive/-R 选项
  - [x] SubTask 1.2: 实现目录递归加密逻辑
  - [x] SubTask 1.3: 添加文件过滤选项（--include/--exclude）
  - [x] SubTask 1.4: 更新帮助文档

- [x] Task 2: 在 decrypt 命令中添加目录支持
  - [x] SubTask 2.1: 添加 --recursive/-R 选项
  - [x] SubTask 2.2: 实现目录递归解密逻辑
  - [x] SubTask 2.3: 添加文件过滤选项（--include/--exclude）
  - [x] SubTask 2.4: 更新帮助文档

- [x] Task 3: 添加目录处理工具函数
  - [x] SubTask 3.1: 实现目录遍历函数
  - [x] SubTask 3.2: 实现文件匹配函数（glob模式）

- [x] Task 4: 更新 README 文档
  - [x] SubTask 4.1: 添加目录加密解密示例

# Task Dependencies
- [Task 1] 和 [Task 2] 可以并行执行
- [Task 3] 依赖于已完成的工具函数
- [Task 4] 依赖于 [Task 1] 和 [Task 2]