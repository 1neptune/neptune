// Package crypto provides high-level encryption/decryption functionality
// combining Curve25519 key exchange with Sosemanuk stream cipher
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	neptuneCurve25519 "neptune/pkg/curve25519"
	"neptune/pkg/sosemanuk"
)

const (
	// Version is the current encryption format version
	Version = 1

	// KeySize is the size of derived encryption keys (256-bit)
	KeySize = 32

	// NonceSize is the size of the nonce for Sosemanuk (128-bit)
	NonceSize = 16

	// PublicKeySize is the size of Curve25519 public keys
	PublicKeySize = neptuneCurve25519.KeySize

	// PrivateKeySize is the size of Curve25519 private keys
	PrivateKeySize = neptuneCurve25519.KeySize

	// HeaderSize is the total size of the encryption header
	// Version(1) + PublicKey(32) + Nonce(16) = 49 bytes
	HeaderSize = 1 + PublicKeySize + NonceSize
)

var (
	// ErrInvalidVersion is returned when the encryption format version is not supported
	ErrInvalidVersion = errors.New("crypto: invalid or unsupported version")

	// ErrInvalidCiphertext is returned when the ciphertext is too short
	ErrInvalidCiphertext = errors.New("crypto: ciphertext is too short")

	// ErrInvalidKeySize is returned when the key size is invalid
	ErrInvalidKeySize = errors.New("crypto: invalid key size")

	// ErrDeriveKeyFailed is returned when key derivation fails
	ErrDeriveKeyFailed = errors.New("crypto: failed to derive encryption key")

	// ErrInvalidPrivateKey is returned when the private key is invalid
	ErrInvalidPrivateKey = errors.New("crypto: invalid private key")
)

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Version      byte
	SenderPubKey [PublicKeySize]byte
	Nonce        [NonceSize]byte
	Ciphertext   []byte
}

// KeyPair wraps curve25519.KeyPair for convenience
type KeyPair = neptuneCurve25519.KeyPair

// GenerateKeyPair generates a new Curve25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	return neptuneCurve25519.GenerateKeyPair()
}

// DeriveEncryptionKey derives an encryption key from a shared secret using HKDF-SHA256
// This implements the KDF (Key Derivation Function) using HKDF with SHA-256
//
// Parameters:
//   - sharedSecret: The raw shared secret from Curve25519 ECDH
//   - context: Additional context information for domain separation
//
// Returns:
//   - A 256-bit encryption key derived from the shared secret
func DeriveEncryptionKey(sharedSecret []byte, context []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, ErrInvalidKeySize
	}

	// Use HKDF-SHA256 to derive a 256-bit encryption key
	// The salt is derived from the context to ensure different keys for different contexts
	salt := sha256.Sum256(context)

	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt[:], context)

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeriveKeyFailed, err)
	}

	return key, nil
}

// DerivePublicKey derives a Curve25519 public key from a private key
func DerivePublicKey(privateKey [PrivateKeySize]byte) [PublicKeySize]byte {
	var publicKey [PublicKeySize]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

// GenerateNonce generates a cryptographically secure random nonce
func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nonce, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// Encrypt encrypts plaintext using the sender's private key and recipient's public key
//
// The encryption process:
//  1. Derive sender's public key from private key
//  2. Compute shared secret using ECDH (Curve25519)
//  3. Derive encryption key using HKDF-SHA256
//  4. Generate random nonce
//  5. Encrypt data using Sosemanuk stream cipher
//  6. Package encrypted data with metadata
//
// For better performance, use EncryptWithKeyPair when you have the full KeyPair
func Encrypt(plaintext []byte, senderPrivateKey [PrivateKeySize]byte, recipientPublicKey [PublicKeySize]byte) (*EncryptedData, error) {
	// Derive sender's public key from private key
	senderPublicKey := DerivePublicKey(senderPrivateKey)

	// Create a temporary KeyPair for encryption
	senderKeyPair := &KeyPair{
		PrivateKey: senderPrivateKey,
		PublicKey:  senderPublicKey,
	}

	return EncryptWithKeyPair(plaintext, senderKeyPair, recipientPublicKey)
}

// EncryptWithKeyPair encrypts plaintext using a complete sender KeyPair
// This is more efficient than Encrypt as it doesn't need to derive the public key
//
// The encryption process:
//  1. Compute shared secret using ECDH (Curve25519)
//  2. Derive encryption key using HKDF-SHA256
//  3. Generate random nonce
//  4. Encrypt data using Sosemanuk stream cipher
//  5. Package encrypted data with metadata
func EncryptWithKeyPair(plaintext []byte, senderKeyPair *KeyPair, recipientPublicKey [PublicKeySize]byte) (*EncryptedData, error) {
	// Compute shared secret using Curve25519
	sharedSecret, err := senderKeyPair.ComputeSharedSecret(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive encryption key using HKDF-SHA256
	// Context includes recipient's public key for domain separation
	context := append([]byte("neptune-encryption"), recipientPublicKey[:]...)
	encryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Generate random nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create Sosemanuk cipher with derived key and nonce
	cipher, err := sosemanuk.New(encryptionKey, nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	return &EncryptedData{
		Version:      Version,
		SenderPubKey: senderKeyPair.PublicKey,
		Nonce:         nonce,
		Ciphertext:   ciphertext,
	}, nil
}

// Decrypt decrypts ciphertext using the recipient's private key
//
// The decryption process:
//  1. Derive recipient's public key from private key
//  2. Compute shared secret using ECDH (Curve25519)
//  3. Derive decryption key using HKDF-SHA256
//  4. Decrypt data using Sosemanuk stream cipher
//
// For better performance, use DecryptWithKeyPair when you have the full KeyPair
func Decrypt(encryptedData *EncryptedData, recipientPrivateKey [PrivateKeySize]byte) ([]byte, error) {
	// Derive recipient's public key from private key
	recipientPublicKey := DerivePublicKey(recipientPrivateKey)

	// Create a temporary KeyPair for decryption
	recipientKeyPair := &KeyPair{
		PrivateKey: recipientPrivateKey,
		PublicKey:  recipientPublicKey,
	}

	return DecryptWithKeyPair(encryptedData, recipientKeyPair)
}

// DecryptWithKeyPair decrypts ciphertext using a complete recipient KeyPair
// This is more efficient than Decrypt as it doesn't need to derive the public key
//
// The decryption process:
//  1. Extract sender's public key from encrypted data
//  2. Compute shared secret using ECDH (Curve25519)
//  3. Derive decryption key using HKDF-SHA256
//  4. Decrypt data using Sosemanuk stream cipher
func DecryptWithKeyPair(encryptedData *EncryptedData, recipientKeyPair *KeyPair) ([]byte, error) {
	// Verify version
	if encryptedData.Version != Version {
		return nil, ErrInvalidVersion
	}

	// Compute shared secret using Curve25519
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(encryptedData.SenderPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive decryption key using HKDF-SHA256
	// Context must match the encryption context
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)
	decryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decryption key: %w", err)
	}

	// Create Sosemanuk cipher with derived key and nonce
	cipher, err := sosemanuk.New(decryptionKey, encryptedData.Nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt the ciphertext
	plaintext := make([]byte, len(encryptedData.Ciphertext))
	cipher.XORKeyStream(plaintext, encryptedData.Ciphertext)

	return plaintext, nil
}

// Serialize serializes EncryptedData to bytes
// Format: [Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes][Ciphertext: variable]
func (ed *EncryptedData) Serialize() []byte {
	totalSize := HeaderSize + len(ed.Ciphertext)
	result := make([]byte, totalSize)

	offset := 0
	result[0] = ed.Version
	offset += 1

	copy(result[offset:], ed.SenderPubKey[:])
	offset += PublicKeySize

	copy(result[offset:], ed.Nonce[:])
	offset += NonceSize

	copy(result[offset:], ed.Ciphertext)

	return result
}

// DeserializeEncryptedData deserializes bytes to EncryptedData
func DeserializeEncryptedData(data []byte) (*EncryptedData, error) {
	if len(data) < HeaderSize {
		return nil, ErrInvalidCiphertext
	}

	offset := 0
	version := data[offset]
	offset += 1

	if version != Version {
		return nil, ErrInvalidVersion
	}

	var senderPubKey [PublicKeySize]byte
	copy(senderPubKey[:], data[offset:])
	offset += PublicKeySize

	var nonce [NonceSize]byte
	copy(nonce[:], data[offset:])
	offset += NonceSize

	ciphertext := make([]byte, len(data)-offset)
	copy(ciphertext, data[offset:])

	return &EncryptedData{
		Version:      version,
		SenderPubKey: senderPubKey,
		Nonce:         nonce,
		Ciphertext:   ciphertext,
	}, nil
}

// EncryptStream 流式加密数据
// 该函数支持从 io.Reader 流式读取数据并加密后写入 io.Writer
// 适用于大文件加密场景，避免一次性加载全部数据到内存
//
// 参数:
//   - plaintext: 明文数据源（io.Reader）
//   - writer: 加密数据输出目标（io.Writer）
//   - senderKeyPair: 发送方的密钥对
//   - recipientPublicKey: 接收方的公钥
//   - bufferSize: 流式处理的缓冲区大小（建议 4KB - 64KB）
//
// 加密流程:
//  1. 计算共享密钥（Curve25519 ECDH）
//  2. 派生加密密钥（HKDF-SHA256）
//  3. 生成随机 nonce
//  4. 写入头部信息（Version + SenderPubKey + Nonce）
//  5. 流式加密数据并写入输出
//
// 返回值:
//   - totalBytes: 加密的明文总字节数
//   - err: 错误信息
func EncryptStream(plaintext io.Reader, writer io.Writer, senderKeyPair *KeyPair, recipientPublicKey [PublicKeySize]byte, bufferSize int) (totalBytes int64, err error) {
	// 计算共享密钥
	sharedSecret, err := senderKeyPair.ComputeSharedSecret(recipientPublicKey)
	if err != nil {
		return 0, fmt.Errorf("计算共享密钥失败: %w", err)
	}

	// 派生加密密钥
	context := append([]byte("neptune-encryption"), recipientPublicKey[:]...)
	encryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("派生加密密钥失败: %w", err)
	}

	// 生成随机 nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return 0, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	// 创建 Sosemanuk cipher
	cipher, err := sosemanuk.New(encryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("创建 cipher 失败: %w", err)
	}

	// 写入头部信息
	// 格式: [Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes]
	header := make([]byte, HeaderSize)
	header[0] = Version
	copy(header[1:], senderKeyPair.PublicKey[:])
	copy(header[1+PublicKeySize:], nonce[:])

	if _, err := writer.Write(header); err != nil {
		return 0, fmt.Errorf("写入头部失败: %w", err)
	}

	// 从全局缓冲区池获取缓冲区
	buf := getGlobalBuffer(bufferSize)
	defer putGlobalBuffer(buf)

	// 流式加密数据
	totalBytes = 0
	for {
		// 从 plaintext 读取数据
		n, readErr := plaintext.Read(buf)
		
		// 如果读取到数据，进行加密
		if n > 0 {
			// 加密数据块
			encryptedChunk := make([]byte, n)
			cipher.XORKeyStream(encryptedChunk, buf[:n])

			// 写入加密数据
			if _, writeErr := writer.Write(encryptedChunk); writeErr != nil {
				return totalBytes, fmt.Errorf("写入加密数据失败: %w", writeErr)
			}

			totalBytes += int64(n)
		}

		// 检查读取状态
		// 如果遇到 EOF，正常退出
		if readErr == io.EOF {
			break
		}
		// 如果遇到其他错误，返回错误
		if readErr != nil {
			return totalBytes, fmt.Errorf("读取明文数据失败: %w", readErr)
		}
		// 如果 n == 0 且没有错误，继续读取
		// 注意：某些 Reader 可能返回 (0, nil)，我们应该继续读取直到遇到 EOF 或错误
	}

	return totalBytes, nil
}

// DecryptStream 流式解密数据
// 该函数支持从 io.Reader 流式读取加密数据并解密后写入 io.Writer
// 适用于大文件解密场景，避免一次性加载全部数据到内存
//
// 参数:
//   - reader: 加密数据源（io.Reader）
//   - plaintextWriter: 解密数据输出目标（io.Writer）
//   - recipientKeyPair: 接收方的密钥对
//   - bufferSize: 流式处理的缓冲区大小（建议 4KB - 64KB）
//
// 解密流程:
//  1. 读取头部信息（Version + SenderPubKey + Nonce）
//  2. 验证版本号
//  3. 计算共享密钥（Curve25519 ECDH）
//  4. 派生解密密钥（HKDF-SHA256）
//  5. 流式解密数据并写入输出
//
// 返回值:
//   - senderPubKey: 发送方公钥
//   - totalBytes: 解密的明文总字节数
//   - err: 错误信息
func DecryptStream(reader io.Reader, plaintextWriter io.Writer, recipientKeyPair *KeyPair, bufferSize int) (senderPubKey [PublicKeySize]byte, totalBytes int64, err error) {
	// 读取头部信息
	header := make([]byte, HeaderSize)
	headerBytesRead, err := io.ReadFull(reader, header)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return senderPubKey, 0, ErrInvalidCiphertext
		}
		return senderPubKey, 0, fmt.Errorf("读取头部失败: %w", err)
	}
	if headerBytesRead != HeaderSize {
		return senderPubKey, 0, ErrInvalidCiphertext
	}

	// 解析头部
	version := header[0]
	if version != Version {
		return senderPubKey, 0, ErrInvalidVersion
	}

	copy(senderPubKey[:], header[1:1+PublicKeySize])
	var nonce [NonceSize]byte
	copy(nonce[:], header[1+PublicKeySize:])

	// 计算共享密钥
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(senderPubKey)
	if err != nil {
		return senderPubKey, 0, fmt.Errorf("计算共享密钥失败: %w", err)
	}

	// 派生解密密钥
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)
	decryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return senderPubKey, 0, fmt.Errorf("派生解密密钥失败: %w", err)
	}

	// 创建 Sosemanuk cipher
	cipher, err := sosemanuk.New(decryptionKey, nonce[:])
	if err != nil {
		return senderPubKey, 0, fmt.Errorf("创建 cipher 失败: %w", err)
	}

	// 从全局缓冲区池获取缓冲区
	buf := getGlobalBuffer(bufferSize)
	defer putGlobalBuffer(buf)

	// 流式解密数据
	totalBytes = 0
	for {
		// 从 reader 读取加密数据
		n, readErr := reader.Read(buf)
		
		// 如果读取到数据，进行解密
		if n > 0 {
			// 解密数据块
			decryptedChunk := make([]byte, n)
			cipher.XORKeyStream(decryptedChunk, buf[:n])

			// 写入解密数据
			if _, writeErr := plaintextWriter.Write(decryptedChunk); writeErr != nil {
				return senderPubKey, totalBytes, fmt.Errorf("写入解密数据失败: %w", writeErr)
			}

			totalBytes += int64(n)
		}

		// 检查读取状态
		// 如果遇到 EOF，正常退出
		if readErr == io.EOF {
			break
		}
		// 如果遇到其他错误，返回错误
		if readErr != nil {
			return senderPubKey, totalBytes, fmt.Errorf("读取加密数据失败: %w", readErr)
		}
		// 如果 n == 0 且没有错误，继续读取
		// 注意：某些 Reader 可能返回 (0, nil)，我们应该继续读取直到遇到 EOF 或错误
	}

	return senderPubKey, totalBytes, nil
}

// getGlobalBuffer 从全局缓冲区池获取缓冲区
// 这是一个辅助函数，用于复用缓冲区
func getGlobalBuffer(size int) []byte {
	// 使用 internal/utils 包中的全局缓冲区池
	// 由于我们在 crypto 包中，我们需要导入 utils 包
	// 为了避免循环导入，我们在这里实现一个简单的缓冲区池
	return globalBufferPool.GetBuffer(size)
}

// putGlobalBuffer 将缓冲区放回全局缓冲区池
func putGlobalBuffer(buf []byte) {
	globalBufferPool.PutBuffer(buf)
}

// 全局缓冲区池实例（crypto 包内部使用）
var globalBufferPool = NewCryptoBufferPool()

// NewCryptoBufferPool 创建一个新的缓冲区池（crypto 包内部使用）
func NewCryptoBufferPool() *CryptoBufferPool {
	return &CryptoBufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, 4096) // 默认容量 4KB
			},
		},
	}
}

// CryptoBufferPool 是 crypto 包内部使用的缓冲区池
type CryptoBufferPool struct {
	pool sync.Pool
}

// GetBuffer 从池中获取一个缓冲区
func (bp *CryptoBufferPool) GetBuffer(size int) []byte {
	buf := bp.pool.Get().([]byte)
	// 如果缓冲区容量不足，创建一个新的
	if cap(buf) < size {
		return make([]byte, size)
	}
	// 设置长度为 size
	return buf[:size]
}

// PutBuffer 将缓冲区放回池中以便复用
func (bp *CryptoBufferPool) PutBuffer(buf []byte) {
	if buf == nil {
		return
	}
	// 重置缓冲区
	buf = buf[:0]
	bp.pool.Put(buf)
}