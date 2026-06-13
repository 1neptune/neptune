# Tasks

- [x] Task 1: 为 encrypt 单文件加密添加进度显示
  - [x] SubTask 1.1: 修改 encrypt.go 中的 EncryptStream 调用，添加进度回调
  - [x] SubTask 1.2: 显示实时进度百分比
  - [x] SubTask 1.3: 测试大文件加密进度显示

- [x] Task 2: 为 encrypt 目录加密添加每个文件进度
  - [x] SubTask 2.1: 修改 encrypt.go 中 encryptDirectory 函数的并行处理
  - [x] SubTask 2.2: 显示每个文件的处理进度
  - [x] SubTask 2.3: 显示整体进度
  - [x] SubTask 2.4: 测试目录加密进度显示

- [x] Task 3: 为 decrypt 目录解密添加每个文件进度
  - [x] SubTask 3.1: 修改 decrypt.go 中 decryptDirectory 函数
  - [x] SubTask 3.2: 显示每个文件的处理进度
  - [x] SubTask 3.3: 显示整体进度
  - [x] SubTask 3.4: 测试目录解密进度显示

- [x] Task 4: 统一进度显示格式
  - [x] SubTask 4.1: 确保 encrypt 和 decrypt 的进度格式一致
  - [x] SubTask 4.2: 测试验证

# Task Dependencies
- Task 1, Task 2, Task 3 可以并行执行
- Task 4 依赖 Task 1, Task 2, Task 3