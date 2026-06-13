# Tasks

- [ ] Task 1: 添加 --remove-source 参数到 decrypt 命令
  - [ ] SubTask 1.1: 添加 decryptRemoveSource 变量
  - [ ] SubTask 1.2: 在 init 函数中注册 --remove-source 参数
  - [ ] SubTask 1.3: 更新命令帮助文档

- [ ] Task 2: 修改 decryptSingleFile 支持删除源文件
  - [ ] SubTask 2.1: 解密成功后关闭输入文件
  - [ ] SubTask 2.2: 根据 --remove-source 参数删除源文件
  - [ ] SubTask 2.3: 处理删除失败的情况（警告但不中断）

- [ ] Task 3: 修改 decryptDirectory 支持删除源文件
  - [ ] SubTask 3.1: 解密成功后关闭输入文件
  - [ ] SubTask 3.2: 根据 --remove-source 参数删除源文件
  - [ ] SubTask 3.3: 处理删除失败的情况（警告但不中断）

- [ ] Task 4: 更新 README.md 文档
  - [ ] SubTask 4.1: 在 decrypt 参数表格中添加 --remove-source
  - [ ] SubTask 4.2: 添加使用示例

- [ ] Task 5: 编译和测试
  - [ ] SubTask 5.1: 编译更新版本
  - [ ] SubTask 5.2: 测试解密删除功能

# Task Dependencies
- Task 2 依赖 Task 1
- Task 3 依赖 Task 1
- Task 4 依赖 Task 1-3
- Task 5 依赖 Task 1-4