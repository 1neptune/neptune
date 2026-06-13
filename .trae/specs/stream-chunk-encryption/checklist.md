# Checklist

## 功能检查
- [x] BufferPool 正确实现 sync.Pool 复用缓冲区
- [x] ParseChunkSize 正确解析 KB/MB/GB 单位
- [x] EncryptStream 流式加密功能正确
- [x] DecryptStream 流式解密功能正确
- [x] Sosemanuk XORKeyStream 性能优化生效
- [x] encrypt 命令支持 --chunk-size 参数
- [x] encrypt 命令支持 --parallel 参数
- [x] decrypt 命令支持 --chunk-size 参数
- [x] decrypt 命令支持 --parallel 参数
- [x] 目录加密支持并行处理

## 性能检查
- [x] 1GB 文件加密内存占用不超过配置的 chunk-size
- [x] sync.Pool 有效减少内存分配次数
- [x] 并行加密目录时处理时间显著减少
- [x] 单文件加密结果与原有方式一致（向后兼容）

## 测试检查
- [x] BufferPool 单元测试通过
- [x] 流式加密/解密单元测试通过
- [x] Sosemanuk 性能基准测试通过
- [x] 大文件加密/解密实测通过
- [x] 并行加密目录实测通过

## 文档检查
- [x] README.md 包含 --chunk-size 参数说明
- [x] README.md 包含 --parallel 参数说明
- [x] README.md 包含大文件加密最佳实践

## 构建检查
- [x] neptune.exe 编译成功
- [x] neptune 编译成功
- [x] 编译后功能正常运行