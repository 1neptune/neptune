# Tasks

- [x] Task 1: 项目初始化与依赖管理
  - [x] SubTask 1.1: 创建 Go 项目目录结构
  - [x] SubTask 1.2: 初始化 go.mod 文件
  - [x] SubTask 1.3: 添加必要的依赖库（如 golang.org/x/crypto）

- [x] Task 2: 实现 Curve25519 密钥交换模块
  - [x] SubTask 2.1: 创建密钥生成函数
  - [x] SubTask 2.2: 实现密钥对序列化/反序列化
  - [x] SubTask 2.3: 实现共享密钥计算（ECDH）
  - [x] SubTask 2.4: 编写单元测试

- [x] Task 3: 实现 Sosemanuk 流密码算法
  - [x] SubTask 3.1: 实现 Sosemanuk 初始化函数
  - [x] SubTask 3.2: 实现密钥调度算法
  - [x] SubTask 3.3: 实现流生成函数
  - [x] SubTask 3.4: 实现加密/解密函数
  - [x] SubTask 3.5: 编写单元测试

- [x] Task 4: 实现加密/解密核心逻辑
  - [x] SubTask 4.1: 实现密钥派生函数（KDF）
  - [x] SubTask 4.2: 实现数据加密流程（密钥交换 + Sosemanuk）
  - [x] SubTask 4.3: 实现数据解密流程
  - [x] SubTask 4.4: 处理加密数据的格式（包含发送方公钥、nonce等元数据）
  - [x] SubTask 4.5: 编写集成测试

- [x] Task 5: 实现命令行接口
  - [x] SubTask 5.1: 使用 cobra 或 flag 包构建 CLI 框架
  - [x] SubTask 5.2: 实现 `keygen` 命令（生成密钥对）
  - [x] SubTask 5.3: 实现 `encrypt` 命令（加密文件或文本）
  - [x] SubTask 5.4: 实现 `decrypt` 命令（解密文件或文本）
  - [x] SubTask 5.5: 实现帮助和版本信息显示

- [x] Task 6: 文件处理与错误处理
  - [x] SubTask 6.1: 实现文件读写功能
  - [x] SubTask 6.2: 实现完善的错误处理和用户提示
  - [x] SubTask 6.3: 添加输入验证

- [x] Task 7: 测试与验证
  - [x] SubTask 7.1: 编写端到端测试用例
  - [x] SubTask 7.2: 测试加密解密的正确性
  - [x] SubTask 7.3: 测试边界情况和错误处理
  - [x] SubTask 7.4: 性能测试

- [x] Task 8: 文档与构建
  - [x] SubTask 8.1: 编写 README 使用说明
  - [x] SubTask 8.2: 添加代码注释
  - [x] SubTask 8.3: 配置跨平台构建脚本

# Task Dependencies
- [Task 2] 和 [Task 3] 可以并行执行
- [Task 4] 依赖于 [Task 2] 和 [Task 3]
- [Task 5] 依赖于 [Task 4]
- [Task 6] 依赖于 [Task 5]
- [Task 7] 依赖于 [Task 6]
- [Task 8] 可以在 [Task 7] 完成后执行