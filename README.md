# Neptune - 安全加密工具

Neptune 是一个基于 **Curve25519 + Sosemanuk** 算法的命令行加密工具，提供安全、高效的端到端加密功能。

## 功能概览

| 命令 | 说明 |
|------|------|
| `keygen` | 生成 Curve25519 密钥对 |
| `encrypt` | 加密文件或目录 |
| `decrypt` | 解密文件或目录 |
| `download` | 下载远程资源 |

## 加密算法

### 密钥交换：Curve25519

Curve25519 是一种现代椭圆曲线密码算法，提供 256-bit 的安全级别。

### 流密码：Sosemanuk

Sosemanuk 是基于 SNOW 2.0 的流密码算法，使用 256-bit 密钥进行加密。

### 加密流程

**加密过程**：
1. 使用 Curve25519 进行 ECDH 密钥交换，生成共享密钥
2. 使用 HKDF-SHA256 派生加密密钥
3. 生成 128-bit 随机 nonce（每次加密唯一）
4. 使用 Sosemanuk 流密码加密数据

**解密过程**：
1. 使用 Curve25519 进行 ECDH 密钥交换，生成相同的共享密钥
2. 使用相同的 HKDF-SHA256 派生解密密钥
3. 使用加密时的 nonce 初始化 Sosemanuk 密码
4. 使用 Sosemanuk 流密码解密数据

## 使用场景

### 场景一：安全传输文件给合作伙伴

```bash
# 1. 生成密钥对
neptune keygen --name company

# 2. 将 company_public.key 发送给合作伙伴

# 3. 使用合作伙伴的公钥加密文件
neptune encrypt \
    --input confidential.pdf \
    --output confidential.ntp \
    --public-key partner_public.key \
    --private-key company_private.key

# 4. 合作伙伴解密
# neptune decrypt --input confidential.ntp --output confidential.pdf --private-key partner_private.key
```

### 场景二：本地备份加密

```bash
# 生成密钥对
neptune keygen --output ~/.secure --name backup

# 加密目录
neptune encrypt \
    --input /home/user/documents \
    --output /backup/encrypted \
    --public-key ~/.secure/backup_public.key \
    --private-key ~/.secure/backup_private.key \
    --recursive

# 解密恢复
neptune decrypt \
    --input /backup/encrypted \
    --output /home/user/restored \
    --private-key ~/.secure/backup_private.key \
    --recursive
```

### 场景三：使用远程密钥

从远程服务器加载密钥进行加密，密钥不落地：

```bash
# 使用远程密钥加密
neptune encrypt \
    --input secret.txt \
    --output secret.ntp \
    --public-key https://keys.example.com/recipient.pub \
    --private-key https://keys.example.com/my.key

# 使用远程密钥解密
neptune decrypt \
    --input encrypted.ntp \
    --output decrypted.txt \
    --private-key https://keys.example.com/my.key
```

### 场景四：下载远程资源

```bash
# 下载单个文件
neptune download \
    --remote-url https://example.com/document.pdf \
    --output ./downloads/

# 下载多个文件
neptune download \
    --remote-url https://example.com/file1.pdf \
    --remote-url https://example.com/file2.txt \
    --output ./downloads/
```

## 命令参考

### keygen - 生成密钥对

```bash
# 生成密钥对（默认保存在当前目录）
neptune keygen

# 指定输出目录和名称
neptune keygen --output ~/.neptune --name mykey
```

### encrypt - 加密文件或目录

```bash
# 基本用法
neptune encrypt \
    --input plaintext.txt \
    --output encrypted.ntp \
    --public-key recipient_public.key \
    --private-key my_private.key

# 简化命令
neptune encrypt -i document.pdf -o document.ntp -p partner.pub -k my.key

# 加密目录
neptune encrypt \
    --input /data/documents \
    --output /data/encrypted \
    --public-key recipient.pub \
    --private-key my.key \
    --recursive

# 只加密指定类型的文件
neptune encrypt \
    --input /data/documents \
    --output /data/encrypted \
    --public-key recipient.pub \
    --private-key my.key \
    --recursive \
    --include "*.pdf" \
    --include "*.docx"

# 加密时排除特定类型的文件
neptune encrypt \
    --input /data/documents \
    --output /data/encrypted \
    --public-key recipient.pub \
    --private-key my.key \
    --recursive \
    --exclude "*.tmp" \
    --exclude "*.log"

# 加密后删除源文件
neptune encrypt \
    --input secret.txt \
    --output secret.ntp \
    --public-key recipient.key \
    --private-key my.key \
    --remove-source
```

### decrypt - 解密文件或目录

```bash
# 基本用法
neptune decrypt \
    --input encrypted.ntp \
    --output plaintext.txt \
    --private-key my_private.key

# 简化命令
neptune decrypt -i document.ntp -o document.pdf -k my.key

# 解密目录
neptune decrypt \
    --input /data/encrypted \
    --output /data/decrypted \
    --private-key my.key \
    --recursive
```

### download - 下载远程资源

```bash
# 下载单个文件
neptune download \
    --remote-url https://example.com/file.pdf \
    --output ./downloads/

# 下载多个文件
neptune download \
    --remote-url https://example.com/file1.pdf \
    --remote-url https://example.com/file2.txt \
    --output ./downloads/

# 下载并重命名
neptune download \
    --remote-url https://example.com/file.pdf \
    --output ./myfile.pdf

# 设置超时时间
neptune download \
    --remote-url https://example.com/large_file.zip \
    --output ./downloads/ \
    --timeout 60
```

## 参数说明

### encrypt 命令参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--input` | `-i` | 输入文件或目录（本地） |
| `--output` | `-o` | 输出文件或目录 |
| `--public-key` | `-p` | 接收者公钥文件或 URL |
| `--private-key` | `-k` | 发送者私钥文件或 URL |
| `--recursive` | `-R` | 递归加密目录 |
| `--include` | - | 只处理匹配的文件模式 |
| `--exclude` | - | 排除匹配的文件模式 |
| `--remove-source` | `-r` | 加密后删除源文件 |
| `--force` | `-f` | 强制覆盖输出文件 |

### decrypt 命令参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--input` | `-i` | 输入文件或目录 |
| `--output` | `-o` | 输出文件或目录 |
| `--private-key` | `-k` | 私钥文件或 URL |
| `--recursive` | `-R` | 递归解密目录 |
| `--force` | `-f` | 强制覆盖输出文件 |

### download 命令参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--remote-url` | - | 远程 URL（可多次使用） |
| `--output` | `-o` | 输出目录或文件路径 |
| `--timeout` | - | HTTP 请求超时时间（秒） |

## 安全提示

1. **密钥管理**: 私钥应妥善保管，切勿泄露给他人
2. **源文件删除**: `--remove-source` 选项会永久删除原始文件，请谨慎使用
3. **备份**: 加密前建议备份重要数据
4. **远程密钥**: 使用远程密钥时确保连接安全（建议使用 HTTPS）

## 许可证

MIT License