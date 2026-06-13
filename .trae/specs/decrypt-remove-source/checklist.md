# Checklist

- [ ] decrypt 命令支持 --remove-source 参数
- [ ] decryptSingleFile 解密成功后删除源文件
- [ ] decryptDirectory 并行解密成功后删除源文件
- [ ] Windows 平台下先关闭文件再删除（避免文件锁定）
- [ ] README.md 包含 --remove-source 参数说明
- [ ] 编译测试通过