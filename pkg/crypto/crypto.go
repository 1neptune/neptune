// Package crypto provides high-level encryption/decryption functionality
// combining Curve25519 key exchange with Sosemanuk stream cipher
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

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

// generateNonce generates a cryptographically secure random nonce
func generateNonce() ([NonceSize]byte, error) {
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
	nonce, err := generateNonce()
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