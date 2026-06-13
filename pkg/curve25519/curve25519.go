// Package curve25519 provides Curve25519 key exchange functionality
package curve25519

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	// KeySize is the size of Curve25519 keys in bytes
	KeySize = 32
)

var (
	ErrInvalidKeySize  = errors.New("invalid key size")
	ErrInvalidKeyPair  = errors.New("invalid key pair")
	ErrInvalidEncoding = errors.New("invalid encoding format")
)

// KeyPair represents a Curve25519 public/private key pair
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair generates a new Curve25519 key pair using cryptographically secure random
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte
	var publicKey [KeySize]byte

	// Use crypto/rand for secure random number generation
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Apply Curve25519 key clamping
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// GenerateKeyPairFromReader generates a key pair from a custom io.Reader
// This is useful for testing with deterministic randomness
func GenerateKeyPairFromReader(r io.Reader) (*KeyPair, error) {
	var privateKey [KeySize]byte
	var publicKey [KeySize]byte

	_, err := io.ReadFull(r, privateKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// ComputeSharedSecret computes a shared secret using ECDH
// Given the other party's public key and our private key, compute the shared secret
func ComputeSharedSecret(privateKey [KeySize]byte, publicKey [KeySize]byte) ([KeySize]byte, error) {
	var sharedSecret [KeySize]byte

	// Perform X25519 scalar multiplication
	curve25519.ScalarMult(&sharedSecret, &privateKey, &publicKey)

	// Check for all-zero shared secret (indicates invalid public key)
	var zero [KeySize]byte
	if sharedSecret == zero {
		return zero, errors.New("invalid public key: resulted in zero shared secret")
	}

	return sharedSecret, nil
}

// ComputeSharedSecretFromKeyPair computes a shared secret from a KeyPair and peer's public key
func (kp *KeyPair) ComputeSharedSecret(peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	return ComputeSharedSecret(kp.PrivateKey, peerPublicKey)
}

// EncodingType defines the encoding format for keys
type EncodingType int

const (
	EncodingHex EncodingType = iota
	EncodingBase64
	EncodingBase64URL
)

// SerializePrivateKey serializes a private key to string using the specified encoding
func SerializePrivateKey(key [KeySize]byte, encoding EncodingType) string {
	switch encoding {
	case EncodingHex:
		return hex.EncodeToString(key[:])
	case EncodingBase64:
		return base64.StdEncoding.EncodeToString(key[:])
	case EncodingBase64URL:
		return base64.URLEncoding.EncodeToString(key[:])
	default:
		return hex.EncodeToString(key[:])
	}
}

// SerializePublicKey serializes a public key to string using the specified encoding
func SerializePublicKey(key [KeySize]byte, encoding EncodingType) string {
	return SerializePrivateKey(key, encoding)
}

// DeserializePrivateKey deserializes a private key from string using the specified encoding
func DeserializePrivateKey(data string, encoding EncodingType) ([KeySize]byte, error) {
	var key [KeySize]byte
	var decoded []byte
	var err error

	switch encoding {
	case EncodingHex:
		decoded, err = hex.DecodeString(data)
	case EncodingBase64:
		decoded, err = base64.StdEncoding.DecodeString(data)
	case EncodingBase64URL:
		decoded, err = base64.URLEncoding.DecodeString(data)
	default:
		decoded, err = hex.DecodeString(data)
	}

	if err != nil {
		return key, fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(decoded) != KeySize {
		return key, ErrInvalidKeySize
	}

	copy(key[:], decoded)
	return key, nil
}

// DeserializePublicKey deserializes a public key from string using the specified encoding
func DeserializePublicKey(data string, encoding EncodingType) ([KeySize]byte, error) {
	return DeserializePrivateKey(data, encoding)
}

// SerializeKeyPair serializes both keys in a key pair to strings
func SerializeKeyPair(kp *KeyPair, encoding EncodingType) (privateKey, publicKey string) {
	return SerializePrivateKey(kp.PrivateKey, encoding), SerializePublicKey(kp.PublicKey, encoding)
}

// DeserializeKeyPair deserializes a key pair from strings
func DeserializeKeyPair(privateKeyStr, publicKeyStr string, encoding EncodingType) (*KeyPair, error) {
	privateKey, err := DeserializePrivateKey(privateKeyStr, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	publicKey, err := DeserializePublicKey(publicKeyStr, encoding)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize public key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// SaveKeyPairToFile saves a key pair to a file
// Format: first line is private key, second line is public key
func SaveKeyPairToFile(kp *KeyPair, filename string, encoding EncodingType) error {
	privateKeyStr, publicKeyStr := SerializeKeyPair(kp, encoding)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	// Write private key on first line
	_, err = fmt.Fprintln(file, privateKeyStr)
	if err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key on second line
	_, err = fmt.Fprintln(file, publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadKeyPairFromFile loads a key pair from a file
func LoadKeyPairFromFile(filename string, encoding EncodingType) (*KeyPair, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %w", err)
	}
	defer file.Close()

	var privateKeyStr, publicKeyStr string

	// Read private key from first line
	_, err = fmt.Fscanln(file, &privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Read public key from second line
	_, err = fmt.Fscanln(file, &publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return DeserializeKeyPair(privateKeyStr, publicKeyStr, encoding)
}

// LoadKeyPairFromBytes loads a key pair from byte data
// Data format: first line is private key, second line is public key
func LoadKeyPairFromBytes(data []byte, encoding EncodingType) (*KeyPair, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var privateKeyStr, publicKeyStr string

	// Read private key from first line
	if scanner.Scan() {
		privateKeyStr = strings.TrimSpace(scanner.Text())
	} else {
		return nil, fmt.Errorf("failed to read private key: no data")
	}

	// Read public key from second line
	if scanner.Scan() {
		publicKeyStr = strings.TrimSpace(scanner.Text())
	} else {
		return nil, fmt.Errorf("failed to read public key: no data")
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan key data: %w", err)
	}

	return DeserializeKeyPair(privateKeyStr, publicKeyStr, encoding)
}

// SavePublicKeyToFile saves only a public key to a file
func SavePublicKeyToFile(publicKey [KeySize]byte, filename string, encoding EncodingType) error {
	publicKeyStr := SerializePublicKey(publicKey, encoding)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer file.Close()

	_, err = fmt.Fprintln(file, publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadPublicKeyFromFile loads a public key from a file
func LoadPublicKeyFromFile(filename string, encoding EncodingType) ([KeySize]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("failed to open public key file: %w", err)
	}
	defer file.Close()

	var publicKeyStr string
	_, err = fmt.Fscanln(file, &publicKeyStr)
	if err != nil {
		return [KeySize]byte{}, fmt.Errorf("failed to read public key: %w", err)
	}

	return DeserializePublicKey(publicKeyStr, encoding)
}

// LoadPublicKeyFromBytes loads a public key from byte data
func LoadPublicKeyFromBytes(data []byte, encoding EncodingType) ([KeySize]byte, error) {
	publicKeyStr := strings.TrimSpace(string(data))
	return DeserializePublicKey(publicKeyStr, encoding)
}

// String returns a safe string representation of the key pair
// Private key is masked for security
func (kp *KeyPair) String() string {
	return fmt.Sprintf("KeyPair{PublicKey: %s, PrivateKey: [REDACTED]}", 
		SerializePublicKey(kp.PublicKey, EncodingHex))
}

// SafeString returns a string with both keys masked
func (kp *KeyPair) SafeString() string {
	return "KeyPair{PublicKey: [REDACTED], PrivateKey: [REDACTED]}"
}