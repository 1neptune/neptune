# Neptune

A secure cross-platform file encryption tool using Curve25519 key exchange and Sosemanuk stream cipher.

**Version**: v1.2.19 (Build Date: 2026-06-26)

## Features

- **Cross-Platform**: Windows, Linux
- **Authenticated Encryption**: Curve25519 ECDH key exchange + Sosemanuk stream cipher
- **Streaming Processing**: Memory-efficient encryption/decryption for files of any size
- **Directory Support**: Recursive encryption/decryption with file pattern filtering
- **Parallel Processing**: Multi-threaded batch processing for directories
- **Remote Keys**: Load keys from HTTP/HTTPS URLs with automatic memory cleanup
- **Memory Security**: Automatic zeroing of sensitive data (keys, nonces, shared secrets)
- **Disk-Scan Mode**: Encrypt/decrypt files across all disks without specifying input path
- **System Directory Exclusion**: Automatically skips recycle bin directories on Windows and core system directories (/bin, /boot, /dev, /lib, /lib64, /proc, /sbin, /sys, /media, /mnt) on Linux
- **Duplicate Encryption Detection**: Skips already-encrypted files (.ntp)
- **Auto Remove Source**: Original files are always removed after successful encryption/decryption (using os.Remove with retry mechanism)
- **File Download**: Download files from remote URLs with memory cleanup

## Encryption Algorithm

Neptune uses **authenticated encryption** with Curve25519 key exchange and Sosemanuk stream cipher:

1. **Key Exchange**: ECDH using Curve25519 to derive a shared secret
2. **Key Derivation**: HKDF-SHA256 to derive encryption key from shared secret
3. **Stream Cipher**: Sosemanuk for fast stream encryption
4. **Nonce**: 16-byte random nonce for each encryption

**Encrypted File Format**:
```
[Version: 1 byte][Sender Public Key: 32 bytes][Nonce: 16 bytes][Ciphertext: N bytes]
```

**File Extension**: `.ntp`

## Why Both Private and Public Keys for Encryption?

Neptune uses **authenticated encryption** with dual-key approach:

1. **Your Private Key**: Proves you are the sender. The encrypted file embeds your public key, allowing the recipient to verify who encrypted it.
2. **Recipient's Public Key**: Ensures only the recipient can decrypt. The shared secret is derived from your private key and their public key.

This provides authentication, confidentiality, and non-repudiation.

## Commands

### version

Display version and build information.

```bash
neptune version
```

**Output**:
```
Neptune Encryption Tool
Version:    v1.2.20
Build Date: 2026-06-26
Algorithm:  Curve25519 + Sosemanuk
```

---

### keygen

Generate a Curve25519 key pair.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--encoding` | `-e` | `hex` | Key encoding format (hex, base64, base64url) |
| `--name` | `-n` | `neptune` | Base name for key files |
| `--output` | `-o` | `.` | Output directory for key files |

**Generated Files**:
- `<name>_private.key` - Your private key (keep secure)
- `<name>_public.key` - Your public key (share with others)

**Examples**:
```bash
# Generate with default settings (hex, current directory)
neptune keygen

# Generate with base64 encoding
neptune keygen --encoding base64

# Generate with custom name and output directory
neptune keygen --name alice --output ./keys
```

---

### encrypt

Encrypt a file or directory.

**Required Flags**:

| Flag | Short | Description |
|------|-------|-------------|
| `--public-key` | `-p` | Recipient's public key file or URL |
| `--private-key` | `-k` | Your private key file or URL |

**Optional Flags**:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--input` | `-i` | *(required for single/directory mode)* | Input file or directory (local only) |
| `--output` | `-o` | *(input location)* | Output directory for encrypted files |
| `--key-encoding` | `-e` | `hex` | Key encoding format (hex, base64, base64url) |
| `--include` | | `[]` | Include files matching pattern (multiple allowed) |
| `--exclude` | | `[]` | Exclude files matching pattern (multiple allowed) |
| `--chunk-size` | | `64KB` | Buffer size for streaming (e.g., 64KB, 1MB, 4MB) |
| `--parallel` | | `1` | Number of parallel processes for directories (1-10) |
| `--timeout` | | `30` | HTTP request timeout in seconds |

**Auto-Enabled Behaviors** (always on):
- **Force overwrite**: Existing output files are always overwritten
- **Remove source**: Original files are always removed after successful encryption
- **Recursive**: Directories are always processed recursively
- **Skip encrypted**: Already-encrypted files (.ntp) are automatically skipped

**Output Naming**: `document.pdf` → `document.pdf.ntp`

**Disk-Scan Mode**:
When `--input` is not specified, Neptune enters disk-scan mode:
- **Windows**: Scans all disks except C:\ drive root, scans all user desktops (C:\Users\*\Desktop), excludes recycle bin directories ($recycle.bin, recycler)
- **Linux**: Scans root filesystem (/), excludes core system directories (/bin, /boot, /dev, /lib, /lib64, /proc, /sbin, /sys, /media, /mnt)
- `--include` is required in this mode
- Default `--chunk-size`: 4MB
- Default `--parallel`: 8

**Examples**:
```bash
# Encrypt a single file
neptune encrypt --input document.pdf --public-key recipient.key --private-key my.key

# Encrypt a file to different directory
neptune encrypt --input document.pdf --output ./encrypted --public-key recipient.key --private-key my.key

# Encrypt a directory recursively
neptune encrypt --input ./documents --public-key recipient.key --private-key my.key

# Encrypt only PDF files in a directory
neptune encrypt --input ./documents --include "*.pdf" --public-key recipient.key --private-key my.key

# Encrypt with multiple include patterns
neptune encrypt --input ./data --include "*.pdf" --include "*.docx" --include "*.xlsx" --public-key recipient.key --private-key my.key

# Encrypt with remote keys from HTTPS
neptune encrypt --input data.txt --public-key https://keyserver.com/pub.key --private-key https://keyserver.com/priv.key

# Encrypt with parallel processing (8 threads)
neptune encrypt --input ./documents --parallel 8 --public-key recipient.key --private-key my.key

# Encrypt with larger chunk size (4MB)
neptune encrypt --input bigfile.iso --chunk-size 4MB --public-key recipient.key --private-key my.key

# Disk-scan mode: encrypt all PDF files across all disks
neptune encrypt --include "*.pdf" --public-key recipient.key --private-key my.key
```

---

### decrypt

Decrypt a file or directory.

**Required Flags**:

| Flag | Short | Description |
|------|-------|-------------|
| `--private-key` | `-k` | Your private key file or URL |

**Optional Flags**:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--input` | `-i` | *(required for single/directory mode)* | Input file or directory (local only) |
| `--output` | `-o` | *(input location)* | Output directory for decrypted files |
| `--key-encoding` | `-e` | `hex` | Key encoding format (hex, base64, base64url) |
| `--include` | | `["*.ntp"]` | Include files matching pattern (multiple allowed) |
| `--exclude` | | `[]` | Exclude files matching pattern (multiple allowed) |
| `--chunk-size` | | `64KB` | Buffer size for streaming (e.g., 64KB, 1MB, 4MB) |
| `--parallel` | | `1` | Number of parallel processes for directories (1-10) |
| `--timeout` | | `30` | HTTP request timeout in seconds |

**Auto-Enabled Behaviors** (always on):
- **Force overwrite**: Existing output files are always overwritten
- **Remove source**: Encrypted source files are always removed after successful decryption
- **Recursive**: Directories are always processed recursively
- **Skip non-encrypted**: Non-.ntp files are automatically skipped

**Output Naming**: `document.pdf.ntp` → `document.pdf`

**Disk-Scan Mode**:
When `--input` is not specified, Neptune enters disk-scan mode:
- **Windows**: Scans all disks except C:\ drive root, scans all user desktops (C:\Users\*\Desktop), excludes recycle bin directories ($recycle.bin, recycler)
- **Linux**: Scans root filesystem (/), excludes core system directories (/bin, /boot, /dev, /lib, /lib64, /proc, /sbin, /sys, /media, /mnt)
- `--include` is required in this mode
- Default `--chunk-size`: 4MB
- Default `--parallel`: 8

**Examples**:
```bash
# Decrypt a single file
neptune decrypt --input document.pdf.ntp --private-key my.key

# Decrypt a file to different directory
neptune decrypt --input document.pdf.ntp --output ./decrypted --private-key my.key

# Decrypt a directory recursively
neptune decrypt --input ./encrypted --private-key my.key

# Decrypt only .ntp files in a directory
neptune decrypt --input ./files --include "*.ntp" --private-key my.key

# Decrypt with remote key from HTTPS
neptune decrypt --input data.ntp --private-key https://keyserver.com/priv.key

# Decrypt with parallel processing (8 threads)
neptune decrypt --input ./encrypted --parallel 8 --private-key my.key

# Disk-scan mode: decrypt all .ntp files across all disks
neptune decrypt --include "*.ntp" --private-key my.key
```

---

### download

Download files from HTTP/HTTPS URLs.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--remote-url` | | *(required)* | Remote URL to download (multiple allowed) |
| `--output` | `-o` | *(current dir / URL filename)* | Output directory or file path |
| `--timeout` | | `30` | HTTP request timeout in seconds |

**Memory Security**: Downloaded data is automatically zeroed from memory after writing to disk.

**Examples**:
```bash
# Download a single file to current directory
neptune download --remote-url https://example.com/document.pdf

# Download a file to specific directory
neptune download --remote-url https://example.com/document.pdf --output ./downloads/

# Download multiple files
neptune download --remote-url https://example.com/file1.pdf --remote-url https://example.com/file2.txt --output ./downloads/

# Download and rename
neptune download --remote-url https://example.com/document.pdf --output ./myfile.pdf
```

## Real-World Scenarios

### Scenario 1: Secure File Transfer Between Users

Alice wants to send encrypted documents to Bob.

```bash
# Alice generates her key pair
neptune keygen --name alice --output ./keys
# Creates: keys/alice_private.key, keys/alice_public.key

# Bob generates his key pair
neptune keygen --name bob --output ./keys
# Creates: keys/bob_private.key, keys/bob_public.key

# Alice encrypts the document for Bob (uses Bob's public key, her private key)
neptune encrypt --input report.pdf --public-key keys/bob_public.key --private-key keys/alice_private.key
# Creates: report.pdf.ntp (original report.pdf is removed)

# Bob decrypts the document (uses his private key)
neptune decrypt --input report.pdf.ntp --private-key keys/bob_private.key
# Creates: report.pdf (report.pdf.ntp is removed)
```

### Scenario 2: Secure Backup with Remote Key Server

Store keys on a secure HTTPS server and encrypt local files.

```bash
# Encrypt local files using remote keys
neptune encrypt --input ./daily_backup --output ./encrypted_backup \
  --public-key https://keyserver.company.com/public.key \
  --private-key https://keyserver.company.com/private.key

# Decrypt when needed
neptune decrypt --input ./encrypted_backup --output ./restored_backup \
  --private-key https://keyserver.company.com/private.key
```

### Scenario 3: Bulk Encryption Across All Disks

Encrypt all sensitive documents on the entire system.

```bash
# Encrypt all PDF, DOCX, and XLSX files across all disks
neptune encrypt \
  --include "*.pdf" --include "*.docx" --include "*.xlsx" \
  --public-key recipient.key --private-key my.key

# Decrypt all encrypted files
neptune decrypt --include "*.ntp" --private-key my.key
```

### Scenario 4: Encrypting a Large File with Streaming

Encrypt a very large file efficiently with streaming.

```bash
# Encrypt a large ISO file with 4MB chunk size
neptune encrypt --input huge_backup.iso --chunk-size 4MB --public-key recipient.key --private-key my.key

# Decrypt with same chunk size
neptune decrypt --input huge_backup.iso.ntp --chunk-size 4MB --private-key my.key
```

### Scenario 5: Parallel Directory Encryption

Speed up encryption of many files using parallel processing.

```bash
# Encrypt directory with 8 parallel threads
neptune encrypt --input ./documents --parallel 8 --public-key recipient.key --private-key my.key

# Decrypt with parallel processing
neptune decrypt --input ./documents --parallel 8 --private-key my.key
```

## Memory Security

Neptune implements multiple memory security measures:

- **Key Zeroing**: Encryption/decryption keys are zeroed from memory after use
- **Nonce Zeroing**: Nonces are zeroed from memory after use
- **Shared Secret Zeroing**: ECDH shared secrets are zeroed after key derivation
- **Downloaded Data Zeroing**: Data downloaded from URLs is zeroed after writing to disk
- **Remote Key Zeroing**: Keys loaded from URLs are zeroed after key pair loading
- **Context Zeroing**: HKDF context data is zeroed after use
- **Sender Public Key Zeroing**: Sender public key references are zeroed after use

All zeroing operations use `SecureZeroMemory` to overwrite sensitive data with zeros before releasing memory.

## Build from Source

### Prerequisites

- Go 1.21 or higher
- Git

### Build Commands

```bash
# Clone the repository
git clone https://github.com/1neptune/neptune.git
cd neptune

# Build for current platform
go build -ldflags="-s -w" -trimpath -o build/neptune ./cmd/neptune

# Build for Windows x64
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o build/neptune.exe ./cmd/neptune

# Build for Linux x64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o build/neptune ./cmd/neptune
```

## File Format Specification

### Encrypted File Header

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 byte | Version | Encryption format version (currently 0x01) |
| 1 | 32 bytes | Sender Public Key | Curve25519 public key of the sender |
| 33 | 16 bytes | Nonce | Random nonce for Sosemanuk cipher |
| 49 | N bytes | Ciphertext | Encrypted data |

**Total Header Size**: 49 bytes

## License

See LICENSE file for details.
