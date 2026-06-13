# Tasks

- [x] Task 1: 添加缓冲区池工具
  - [x] SubTask 1.1: 在 `internal/utils/utils.go` 中创建 `BufferPool` 结构体，使用 `sync.Pool` 实现
  - [x] SubTask 1.2: 实现 `GetBuffer(size int)` 和 `PutBuffer(buf []byte)` 方法
  - [x] SubTask 1.3: 添加缓冲区大小解析函数 `ParseChunkSize(sizeStr string) (int, error)`
  - [x] SubTask 1.4: 编写单元测试验证缓冲区池功能

- [x] Task 2: 添加流式加密/解密接口
  - [x] SubTask 2.1: 在 `pkg/crypto/crypto.go` 中添加 `EncryptStream` 函数
  - [x] SubTask 2.2: 在 `pkg/crypto/crypto.go` 中添加 `DecryptStream` 函数
  - [x] SubTask 2.3: 实现流式读写逻辑，支持 io.Reader/io.Writer 接口
  - [x] SubTask 2.4: 编写单元测试验证流式加密/解密正确性

- [x] Task 3: 优化 Sosemanuk XORKeyStream 性能
  - [x] SubTask 3.1: 在 `pkg/sosemanuk/sosemanuk.go` 中优化 `XORKeyStream` 方法
  - [x] SubTask 3.2: 减少函数调用开销，批量处理 keystream
  - [x] SubTask 3.3: 编写性能基准测试对比优化前后

- [x] Task 4: 修改 encrypt 命令使用流式处理
  - [x] SubTask 4.1: 添加 `--chunk-size` 参数到 encrypt 命令
  - [x] SubTask 4.2: 添加 `--parallel` 参数到 encrypt 命令
  - [x] SubTask 4.3: 修改 `encryptSingleFileOrText` 使用流式加密
  - [x] SubTask 4.4: 修改 `encryptDirectory` 支持并行处理
  - [x] SubTask 4.5: 使用 BufferPool 复用缓冲区

- [x] Task 5: 修改 decrypt 命令使用流式处理
  - [x] SubTask 5.1: 添加 `--chunk-size` 参数到 decrypt 命令
  - [x] SubTask 5.2: 添加 `--parallel` 参数到 decrypt 命令
  - [x] SubTask 5.3: 修改 `decryptSingleFile` 使用流式解密
  - [x] SubTask 5.4: 修改 `decryptDirectory` 支持并行处理
  - [x] SubTask 5.5: 使用 BufferPool 复用缓冲区

- [x] Task 6: 更新 README.md 文档
  - [x] SubTask 6.1: 添加 `--chunk-size` 参数说明和使用示例
  - [x] SubTask 6.2: 添加 `--parallel` 参数说明和使用示例
  - [x] SubTask 6.3: 添加大文件加密最佳实践建议

- [x] Task 7: 编译和测试
  - [x] SubTask 7.1: 编译 neptune.exe 和 neptune
  - [x] SubTask 7.2: 测试大文件加密/解密功能
  - [x] SubTask 7.3: 测试并行加密目录功能
  - [x] SubTask 7.4: 验证内存占用符合预期

# Task Dependencies
- Task 2 依赖 Task 1（需要 BufferPool）
- Task 4 依赖 Task 2（需要 EncryptStream）
- Task 5 依赖 Task 2（需要 DecryptStream）
- Task 6 依赖 Task 4, Task 5（需要功能完成）
- Task 7 依赖 Task 1-6（需要所有功能完成）

# Parallelizable Work
- Task 1 和 Task 3 可以并行执行
- Task 4 和 Task 5 可以并行执行（在 Task 2 完成后）