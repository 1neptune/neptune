package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"testing"
)

// TestDeriveEncryptionKey tests the HKDF-SHA256 key derivation function
func TestDeriveEncryptionKey(t *testing.T) {
	tests := []struct {
		name          string
		sharedSecret  []byte
		context       []byte
		expectedError bool
	}{
		{
			name:         "valid derivation with 32-byte secret",
			sharedSecret: make([]byte, 32),
			context:      []byte("test-context"),
		},
		{
			name:         "valid derivation with 16-byte secret",
			sharedSecret: make([]byte, 16),
			context:      []byte("another-context"),
		},
		{
			name:         "valid derivation with empty context",
			sharedSecret: make([]byte, 32),
			context:      []byte{},
		},
		{
			name:          "invalid derivation with empty secret",
			sharedSecret:  []byte{},
			context:       []byte("test-context"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill shared secret with random data if not empty
			if len(tt.sharedSecret) > 0 {
				io.ReadFull(rand.Reader, tt.sharedSecret)
			}

			key, err := DeriveEncryptionKey(tt.sharedSecret, tt.context)

			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Verify key size
			if len(key) != KeySize {
				t.Errorf("expected key size %d, got %d", KeySize, len(key))
			}

			// Verify key is deterministic (same inputs should produce same output)
			key2, err := DeriveEncryptionKey(tt.sharedSecret, tt.context)
			if err != nil {
				t.Errorf("unexpected error on second derivation: %v", err)
				return
			}

			if !bytes.Equal(key, key2) {
				t.Errorf("key derivation is not deterministic")
			}

			// Verify different contexts produce different keys
			if len(tt.context) > 0 {
				differentContext := append(tt.context, byte(0x01))
				key3, err := DeriveEncryptionKey(tt.sharedSecret, differentContext)
				if err != nil {
					t.Errorf("unexpected error on different context: %v", err)
					return
				}

				if bytes.Equal(key, key3) {
					t.Errorf("different contexts should produce different keys")
				}
			}
		})
	}
}

// TestDerivePublicKey tests public key derivation from private key
func TestDerivePublicKey(t *testing.T) {
	// Generate a key pair
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Derive public key from private key
	derivedPublicKey := DerivePublicKey(keyPair.PrivateKey)

	// Verify derived public key matches the original
	if !bytes.Equal(derivedPublicKey[:], keyPair.PublicKey[:]) {
		t.Errorf("derived public key does not match original")
		t.Errorf("original:  %s", hex.EncodeToString(keyPair.PublicKey[:]))
		t.Errorf("derived:   %s", hex.EncodeToString(derivedPublicKey[:]))
	}
}

// TestEncryptDecrypt tests the basic encryption and decryption flow
func TestEncryptDecrypt(t *testing.T) {
	// Generate sender and recipient key pairs
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message.")

	// Encrypt with sender's private key and recipient's public key
	encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Verify encrypted data structure
	if encryptedData.Version != Version {
		t.Errorf("expected version %d, got %d", Version, encryptedData.Version)
	}

	if len(encryptedData.Nonce) != NonceSize {
		t.Errorf("expected nonce size %d, got %d", NonceSize, len(encryptedData.Nonce))
	}

	if len(encryptedData.Ciphertext) != len(plaintext) {
		t.Errorf("expected ciphertext size %d, got %d", len(plaintext), len(encryptedData.Ciphertext))
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(encryptedData.Ciphertext, plaintext) {
		t.Errorf("ciphertext should not equal plaintext")
	}

	// Decrypt with recipient's private key
	decryptedPlaintext, err := DecryptWithKeyPair(encryptedData, recipientKeyPair)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Verify decrypted plaintext matches original
	if !bytes.Equal(decryptedPlaintext, plaintext) {
		t.Errorf("decrypted plaintext does not match original")
		t.Errorf("original:   %s", plaintext)
		t.Errorf("decrypted:  %s", decryptedPlaintext)
	}
}

// TestEncryptDecryptWithPrivateKeyOnly tests encryption/decryption using only private keys
func TestEncryptDecryptWithPrivateKeyOnly(t *testing.T) {
	// Generate sender and recipient key pairs
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	plaintext := []byte("Testing with private keys only")

	// Encrypt using only private key
	encryptedData, err := Encrypt(plaintext, senderKeyPair.PrivateKey, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Decrypt using only private key
	decryptedPlaintext, err := Decrypt(encryptedData, recipientKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Verify decrypted plaintext matches original
	if !bytes.Equal(decryptedPlaintext, plaintext) {
		t.Errorf("decrypted plaintext does not match original")
	}
}

// TestEncryptDecryptDifferentSizes tests encryption/decryption with different data sizes
func TestEncryptDecryptDifferentSizes(t *testing.T) {
	sizes := []int{
		0,       // empty
		1,       // single byte
		16,      // small
		1024,    // 1KB
		4096,    // 4KB
		16384,   // 16KB
		65536,   // 64KB
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			senderKeyPair, err := GenerateKeyPair()
			if err != nil {
				t.Fatalf("failed to generate sender key pair: %v", err)
			}

			recipientKeyPair, err := GenerateKeyPair()
			if err != nil {
				t.Fatalf("failed to generate recipient key pair: %v", err)
			}

			plaintext := make([]byte, size)
			if size > 0 {
				io.ReadFull(rand.Reader, plaintext)
			}

			encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			decryptedPlaintext, err := DecryptWithKeyPair(encryptedData, recipientKeyPair)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			if !bytes.Equal(decryptedPlaintext, plaintext) {
				t.Errorf("decrypted plaintext does not match original for size %d", size)
			}
		})
	}
}

// TestMultipleEncryptions tests that multiple encryptions produce different ciphertexts
func TestMultipleEncryptions(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	plaintext := []byte("Same plaintext, different ciphertexts")

	// Encrypt the same plaintext multiple times
	encryptedData1, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt first time: %v", err)
	}

	encryptedData2, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt second time: %v", err)
	}

	// Verify ciphertexts are different (due to random nonce)
	if bytes.Equal(encryptedData1.Ciphertext, encryptedData2.Ciphertext) {
		t.Errorf("multiple encryptions should produce different ciphertexts")
	}

	// Verify nonces are different
	if bytes.Equal(encryptedData1.Nonce[:], encryptedData2.Nonce[:]) {
		t.Errorf("multiple encryptions should use different nonces")
	}

	// Both should decrypt to the same plaintext
	decrypted1, err := DecryptWithKeyPair(encryptedData1, recipientKeyPair)
	if err != nil {
		t.Fatalf("failed to decrypt first ciphertext: %v", err)
	}

	decrypted2, err := DecryptWithKeyPair(encryptedData2, recipientKeyPair)
	if err != nil {
		t.Fatalf("failed to decrypt second ciphertext: %v", err)
	}

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("both decryptions should produce the original plaintext")
	}
}

// TestSerializeDeserialize tests serialization and deserialization of encrypted data
func TestSerializeDeserialize(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	plaintext := []byte("Test serialization and deserialization")

	encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Serialize
	serialized := encryptedData.Serialize()

	// Verify serialized size
	expectedSize := HeaderSize + len(plaintext)
	if len(serialized) != expectedSize {
		t.Errorf("expected serialized size %d, got %d", expectedSize, len(serialized))
	}

	// Deserialize
	deserializedData, err := DeserializeEncryptedData(serialized)
	if err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	// Verify deserialized data matches original
	if deserializedData.Version != encryptedData.Version {
		t.Errorf("version mismatch")
	}

	if !bytes.Equal(deserializedData.SenderPubKey[:], encryptedData.SenderPubKey[:]) {
		t.Errorf("sender public key mismatch")
	}

	if !bytes.Equal(deserializedData.Nonce[:], encryptedData.Nonce[:]) {
		t.Errorf("nonce mismatch")
	}

	if !bytes.Equal(deserializedData.Ciphertext, encryptedData.Ciphertext) {
		t.Errorf("ciphertext mismatch")
	}

	// Decrypt deserialized data
	decryptedPlaintext, err := DecryptWithKeyPair(deserializedData, recipientKeyPair)
	if err != nil {
		t.Fatalf("failed to decrypt deserialized data: %v", err)
	}

	if !bytes.Equal(decryptedPlaintext, plaintext) {
		t.Errorf("decrypted plaintext from deserialized data does not match original")
	}
}

// TestDeserializeErrors tests error handling in deserialization
func TestDeserializeErrors(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		expectedError error
	}{
		{
			name:          "too short data",
			data:          make([]byte, HeaderSize-1),
			expectedError: ErrInvalidCiphertext,
		},
		{
			name:          "invalid version",
			data:          append([]byte{0x02}, make([]byte, HeaderSize-1)...),
			expectedError: ErrInvalidVersion,
		},
		{
			name:          "empty data",
			data:          []byte{},
			expectedError: ErrInvalidCiphertext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeEncryptedData(tt.data)
			if err != tt.expectedError {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}

// TestDecryptWithWrongKey tests decryption with wrong private key
func TestDecryptWithWrongKey(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	// Generate a different key pair (wrong recipient)
	wrongKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate wrong key pair: %v", err)
	}

	plaintext := []byte("This should not decrypt correctly")

	encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Try to decrypt with wrong private key
	decryptedPlaintext, err := DecryptWithKeyPair(encryptedData, wrongKeyPair)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Decrypted data should not match original plaintext
	if bytes.Equal(decryptedPlaintext, plaintext) {
		t.Errorf("decryption with wrong key should not produce correct plaintext")
	}
}

// TestDecryptInvalidVersion tests decryption with invalid version
func TestDecryptInvalidVersion(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	plaintext := []byte("Test invalid version")

	encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Modify version to invalid value
	encryptedData.Version = 0x02

	// Try to decrypt
	_, err = DecryptWithKeyPair(encryptedData, recipientKeyPair)
	if err != ErrInvalidVersion {
		t.Errorf("expected error %v, got %v", ErrInvalidVersion, err)
	}
}

// TestBidirectionalCommunication tests bidirectional communication between two parties
func TestBidirectionalCommunication(t *testing.T) {
	// Alice and Bob each have their own key pair
	aliceKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate Alice's key pair: %v", err)
	}

	bobKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate Bob's key pair: %v", err)
	}

	// Alice sends message to Bob
	aliceMessage := []byte("Hello Bob, this is Alice!")
	encryptedFromAlice, err := EncryptWithKeyPair(aliceMessage, aliceKeyPair, bobKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	// Bob decrypts Alice's message
	bobReceived, err := DecryptWithKeyPair(encryptedFromAlice, bobKeyPair)
	if err != nil {
		t.Fatalf("Bob failed to decrypt Alice's message: %v", err)
	}

	if !bytes.Equal(bobReceived, aliceMessage) {
		t.Errorf("Bob received wrong message from Alice")
	}

	// Bob sends message to Alice
	bobMessage := []byte("Hello Alice, this is Bob!")
	encryptedFromBob, err := EncryptWithKeyPair(bobMessage, bobKeyPair, aliceKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Bob failed to encrypt: %v", err)
	}

	// Alice decrypts Bob's message
	aliceReceived, err := DecryptWithKeyPair(encryptedFromBob, aliceKeyPair)
	if err != nil {
		t.Fatalf("Alice failed to decrypt Bob's message: %v", err)
	}

	if !bytes.Equal(aliceReceived, bobMessage) {
		t.Errorf("Alice received wrong message from Bob")
	}
}

// TestEncryptDecryptRoundTrip tests a complete round trip with serialization
func TestEncryptDecryptRoundTrip(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	plaintext := []byte("Complete round trip test with serialization")

	// Encrypt
	encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Serialize
	serialized := encryptedData.Serialize()

	// Deserialize
	deserializedData, err := DeserializeEncryptedData(serialized)
	if err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	// Decrypt
	decryptedPlaintext, err := DecryptWithKeyPair(deserializedData, recipientKeyPair)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Verify
	if !bytes.Equal(decryptedPlaintext, plaintext) {
		t.Errorf("round trip failed: decrypted plaintext does not match original")
	}
}

// TestNonceUniqueness tests that nonces are unique across multiple encryptions
func TestNonceUniqueness(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender key pair: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key pair: %v", err)
	}

	plaintext := []byte("Test nonce uniqueness")

	// Generate many encryptions
	nonces := make(map[string]bool)
	numEncryptions := 100

	for i := 0; i < numEncryptions; i++ {
		encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
		if err != nil {
			t.Fatalf("failed to encrypt at iteration %d: %v", i, err)
		}

		nonceHex := hex.EncodeToString(encryptedData.Nonce[:])
		if nonces[nonceHex] {
			t.Errorf("nonce collision detected at iteration %d", i)
		}
		nonces[nonceHex] = true
	}

	// Verify we have unique nonces
	if len(nonces) != numEncryptions {
		t.Errorf("expected %d unique nonces, got %d", numEncryptions, len(nonces))
	}
}

// TestKeyDerivationConsistency tests that key derivation is consistent
func TestKeyDerivationConsistency(t *testing.T) {
	// Generate two key pairs
	keyPair1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair 1: %v", err)
	}

	keyPair2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair 2: %v", err)
	}

	// Compute shared secret from both directions
	sharedSecret1, err := keyPair1.ComputeSharedSecret(keyPair2.PublicKey)
	if err != nil {
		t.Fatalf("failed to compute shared secret from keyPair1: %v", err)
	}

	sharedSecret2, err := keyPair2.ComputeSharedSecret(keyPair1.PublicKey)
	if err != nil {
		t.Fatalf("failed to compute shared secret from keyPair2: %v", err)
	}

	// Verify shared secrets are identical
	if !bytes.Equal(sharedSecret1[:], sharedSecret2[:]) {
		t.Errorf("shared secrets should be identical")
		t.Errorf("from keyPair1: %s", hex.EncodeToString(sharedSecret1[:]))
		t.Errorf("from keyPair2: %s", hex.EncodeToString(sharedSecret2[:]))
	}

	// Derive encryption keys from both shared secrets
	context := []byte("test-context")
	key1, err := DeriveEncryptionKey(sharedSecret1[:], context)
	if err != nil {
		t.Fatalf("failed to derive key from sharedSecret1: %v", err)
	}

	key2, err := DeriveEncryptionKey(sharedSecret2[:], context)
	if err != nil {
		t.Fatalf("failed to derive key from sharedSecret2: %v", err)
	}

	// Verify derived keys are identical
	if !bytes.Equal(key1, key2) {
		t.Errorf("derived keys should be identical")
	}
}

// BenchmarkEncryptDecrypt benchmarks the encryption and decryption flow
func BenchmarkEncryptDecrypt(b *testing.B) {
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedData, _ := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
		DecryptWithKeyPair(encryptedData, recipientKeyPair)
	}
}

// BenchmarkEncrypt benchmarks encryption alone
func BenchmarkEncrypt(b *testing.B) {
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	}
}

// BenchmarkDecrypt benchmarks decryption alone
func BenchmarkDecrypt(b *testing.B) {
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encryptedData, _ := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptWithKeyPair(encryptedData, recipientKeyPair)
	}
}

// BenchmarkGenerateKeyPair benchmarks key pair generation
func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPair()
	}
}

// BenchmarkDeriveEncryptionKey benchmarks key derivation
func BenchmarkDeriveEncryptionKey(b *testing.B) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	context := []byte("test-context")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveEncryptionKey(sharedSecret, context)
	}
}

// BenchmarkSerializeDeserialize benchmarks serialization/deserialization
func BenchmarkSerializeDeserialize(b *testing.B) {
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	encryptedData, _ := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serialized := encryptedData.Serialize()
		DeserializeEncryptedData(serialized)
	}
}

// TestEncryptDecryptStream 测试基本的流式加密/解密功能
func TestEncryptDecryptStream(t *testing.T) {
	// 生成发送方和接收方密钥对
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成发送方密钥对失败: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成接收方密钥对失败: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message for stream encryption.")

	// 创建缓冲区用于存储加密数据
	encryptedBuffer := &bytes.Buffer{}

	// 流式加密
	bufferSize := 4096 // 4KB 缓冲区
	totalBytes, err := EncryptStream(bytes.NewReader(plaintext), encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, bufferSize)
	if err != nil {
		t.Fatalf("流式加密失败: %v", err)
	}

	// 验证加密的总字节数
	if totalBytes != int64(len(plaintext)) {
		t.Errorf("加密字节数不匹配: 期望 %d, 实际 %d", len(plaintext), totalBytes)
	}

	// 验证加密数据包含头部
	encryptedData := encryptedBuffer.Bytes()
	if len(encryptedData) != HeaderSize+len(plaintext) {
		t.Errorf("加密数据长度不匹配: 期望 %d, 实际 %d", HeaderSize+len(plaintext), len(encryptedData))
	}

	// 流式解密
	decryptedBuffer := &bytes.Buffer{}
	senderPubKey, totalBytes, err := DecryptStream(bytes.NewReader(encryptedData), decryptedBuffer, recipientKeyPair, bufferSize)
	if err != nil {
		t.Fatalf("流式解密失败: %v", err)
	}

	// 验证解密的总字节数
	if totalBytes != int64(len(plaintext)) {
		t.Errorf("解密字节数不匹配: 期望 %d, 实际 %d", len(plaintext), totalBytes)
	}

	// 验证发送方公钥
	if !bytes.Equal(senderPubKey[:], senderKeyPair.PublicKey[:]) {
		t.Errorf("发送方公钥不匹配")
	}

	// 验证解密后的数据
	decryptedPlaintext := decryptedBuffer.Bytes()
	if !bytes.Equal(decryptedPlaintext, plaintext) {
		t.Errorf("解密后的数据不匹配原始数据")
		t.Errorf("原始:   %s", plaintext)
		t.Errorf("解密:   %s", decryptedPlaintext)
	}
}

// TestEncryptDecryptStreamDifferentSizes 测试不同数据大小的流式加密/解密
func TestEncryptDecryptStreamDifferentSizes(t *testing.T) {
	sizes := []int{
		0,       // 空数据
		1,       // 单字节
		16,      // 小数据
		1024,    // 1KB
		4096,    // 4KB
		16384,   // 16KB
		65536,   // 64KB
		131072,  // 128KB
	}

	bufferSizes := []int{
		1024,  // 1KB 缓冲区
		4096,  // 4KB 缓冲区
		16384, // 16KB 缓冲区
	}

	for _, size := range sizes {
		for _, bufferSize := range bufferSizes {
			t.Run(fmt.Sprintf("size_%d_buffer_%d", size, bufferSize), func(t *testing.T) {
				senderKeyPair, err := GenerateKeyPair()
				if err != nil {
					t.Fatalf("生成发送方密钥对失败: %v", err)
				}

				recipientKeyPair, err := GenerateKeyPair()
				if err != nil {
					t.Fatalf("生成接收方密钥对失败: %v", err)
				}

				plaintext := make([]byte, size)
				if size > 0 {
					io.ReadFull(rand.Reader, plaintext)
				}

				// 流式加密
				encryptedBuffer := &bytes.Buffer{}
				totalBytes, err := EncryptStream(bytes.NewReader(plaintext), encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, bufferSize)
				if err != nil {
					t.Fatalf("流式加密失败: %v", err)
				}

				if totalBytes != int64(len(plaintext)) {
					t.Errorf("加密字节数不匹配: 期望 %d, 实际 %d", len(plaintext), totalBytes)
				}

				// 流式解密
				decryptedBuffer := &bytes.Buffer{}
				_, totalBytes, err = DecryptStream(bytes.NewReader(encryptedBuffer.Bytes()), decryptedBuffer, recipientKeyPair, bufferSize)
				if err != nil {
					t.Fatalf("流式解密失败: %v", err)
				}

				if totalBytes != int64(len(plaintext)) {
					t.Errorf("解密字节数不匹配: 期望 %d, 实际 %d", len(plaintext), totalBytes)
				}

				decryptedPlaintext := decryptedBuffer.Bytes()
				if !bytes.Equal(decryptedPlaintext, plaintext) {
					t.Errorf("解密后的数据不匹配原始数据 (size=%d, bufferSize=%d)", size, bufferSize)
				}
			})
		}
	}
}

// TestEncryptStreamCompatibility 测试流式加密与原有加密函数的兼容性
func TestEncryptStreamCompatibility(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成发送方密钥对失败: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成接收方密钥对失败: %v", err)
	}

	plaintext := []byte("Compatibility test between stream and non-stream encryption")

	// 使用原有 EncryptWithKeyPair 函数加密
	encryptedData, err := EncryptWithKeyPair(plaintext, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("原有加密失败: %v", err)
	}

	// 序列化原有加密结果
	serialized := encryptedData.Serialize()

	// 使用流式解密解密原有加密结果
	decryptedBuffer := &bytes.Buffer{}
	bufferSize := 4096
	_, totalBytes, err := DecryptStream(bytes.NewReader(serialized), decryptedBuffer, recipientKeyPair, bufferSize)
	if err != nil {
		t.Fatalf("流式解密原有加密数据失败: %v", err)
	}

	if totalBytes != int64(len(plaintext)) {
		t.Errorf("解密字节数不匹配: 期望 %d, 实际 %d", len(plaintext), totalBytes)
	}

	decryptedPlaintext := decryptedBuffer.Bytes()
	if !bytes.Equal(decryptedPlaintext, plaintext) {
		t.Errorf("流式解密原有加密数据结果不正确")
	}

	// 使用流式加密加密数据
	encryptedBuffer := &bytes.Buffer{}
	_, err = EncryptStream(bytes.NewReader(plaintext), encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, bufferSize)
	if err != nil {
		t.Fatalf("流式加密失败: %v", err)
	}

	// 使用原有 DecryptWithKeyPair 函数解密流式加密结果
	streamEncryptedData := encryptedBuffer.Bytes()
	deserializedData, err := DeserializeEncryptedData(streamEncryptedData)
	if err != nil {
		t.Fatalf("反序列化流式加密数据失败: %v", err)
	}

	decryptedPlaintext2, err := DecryptWithKeyPair(deserializedData, recipientKeyPair)
	if err != nil {
		t.Fatalf("原有解密流式加密数据失败: %v", err)
	}

	if !bytes.Equal(decryptedPlaintext2, plaintext) {
		t.Errorf("原有解密流式加密数据结果不正确")
	}
}

// TestEncryptStreamErrors 测试流式加密的错误处理
func TestEncryptStreamErrors(t *testing.T) {
	senderKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成发送方密钥对失败: %v", err)
	}

	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成接收方密钥对失败: %v", err)
	}

	plaintext := []byte("Test error handling")

	// 测试写入失败
	errorWriter := &errorWriter{shouldFail: true}
	_, err = EncryptStream(bytes.NewReader(plaintext), errorWriter, senderKeyPair, recipientKeyPair.PublicKey, 4096)
	if err == nil {
		t.Errorf("期望写入失败错误，但没有得到错误")
	}

	// 测试读取失败
	errorReader := &errorReader{shouldFail: true}
	encryptedBuffer := &bytes.Buffer{}
	_, err = EncryptStream(errorReader, encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, 4096)
	if err == nil {
		t.Errorf("期望读取失败错误，但没有得到错误")
	}
}

// TestDecryptStreamErrors 测试流式解密的错误处理
func TestDecryptStreamErrors(t *testing.T) {
	recipientKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成接收方密钥对失败: %v", err)
	}

	bufferSize := 4096

	// 测试数据太短
	shortData := make([]byte, HeaderSize-1)
	decryptedBuffer := &bytes.Buffer{}
	_, _, err = DecryptStream(bytes.NewReader(shortData), decryptedBuffer, recipientKeyPair, bufferSize)
	if err != ErrInvalidCiphertext {
		t.Errorf("期望 ErrInvalidCiphertext 错误，得到: %v", err)
	}

	// 测试无效版本
	invalidVersionData := make([]byte, HeaderSize)
	invalidVersionData[0] = 0x02 // 无效版本
	_, _, err = DecryptStream(bytes.NewReader(invalidVersionData), decryptedBuffer, recipientKeyPair, bufferSize)
	if err != ErrInvalidVersion {
		t.Errorf("期望 ErrInvalidVersion 错误，得到: %v", err)
	}

	// 测试写入失败
	senderKeyPair, _ := GenerateKeyPair()
	plaintext := []byte("Test data")
	encryptedBuffer := &bytes.Buffer{}
	EncryptStream(bytes.NewReader(plaintext), encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, bufferSize)

	errorWriter := &errorWriter{shouldFail: true}
	_, _, err = DecryptStream(bytes.NewReader(encryptedBuffer.Bytes()), errorWriter, recipientKeyPair, bufferSize)
	if err == nil {
		t.Errorf("期望写入失败错误，但没有得到错误")
	}
}

// errorWriter 是一个模拟写入失败的 io.Writer
type errorWriter struct {
	shouldFail bool
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	if w.shouldFail {
		return 0, fmt.Errorf("模拟写入失败")
	}
	return len(p), nil
}

// errorReader 是一个模拟读取失败的 io.Reader
type errorReader struct {
	shouldFail bool
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	if r.shouldFail {
		return 0, fmt.Errorf("模拟读取失败")
	}
	return 0, io.EOF
}

// BenchmarkEncryptStream 流式加密性能基准测试
func BenchmarkEncryptStream(b *testing.B) {
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()
	plaintext := make([]byte, 1024*1024) // 1MB 数据
	rand.Read(plaintext)

	bufferSize := 4096 // 4KB 缓冲区

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedBuffer := &bytes.Buffer{}
		EncryptStream(bytes.NewReader(plaintext), encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, bufferSize)
	}
}

// BenchmarkDecryptStream 流式解密性能基准测试
func BenchmarkDecryptStream(b *testing.B) {
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()
	plaintext := make([]byte, 1024*1024) // 1MB 数据
	rand.Read(plaintext)

	bufferSize := 4096 // 4KB 缓冲区

	// 预先加密数据
	encryptedBuffer := &bytes.Buffer{}
	EncryptStream(bytes.NewReader(plaintext), encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, bufferSize)
	encryptedData := encryptedBuffer.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptedBuffer := &bytes.Buffer{}
		DecryptStream(bytes.NewReader(encryptedData), decryptedBuffer, recipientKeyPair, bufferSize)
	}
}

// BenchmarkEncryptStreamDifferentBufferSizes 测试不同缓冲区大小的性能
func BenchmarkEncryptStreamDifferentBufferSizes(b *testing.B) {
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()
	plaintext := make([]byte, 1024*1024) // 1MB 数据
	rand.Read(plaintext)

	bufferSizes := []int{
		1024,   // 1KB
		4096,   // 4KB
		16384,  // 16KB
		65536,  // 64KB
	}

	for _, bufferSize := range bufferSizes {
		b.Run(fmt.Sprintf("buffer_%d", bufferSize), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encryptedBuffer := &bytes.Buffer{}
				EncryptStream(bytes.NewReader(plaintext), encryptedBuffer, senderKeyPair, recipientKeyPair.PublicKey, bufferSize)
			}
		})
	}
}