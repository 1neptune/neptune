// Package curve25519 provides a high-level wrapper around the X25519
// Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol using Curve25519.
//
// Curve25519 is an elliptic curve offering 128 bits of security and designed
// for use in the Elliptic Curve Diffie-Hellman (ECDH) key agreement scheme.
// It is one of the fastest ECC curves and is not covered by any known patents.
//
// This package provides functionality for:
//   - Generating Curve25519 key pairs
//   - Computing shared secrets via ECDH
//   - Serializing/deserializing keys in hex, base64, and base64url formats
//   - Saving/loading key pairs and public keys to/from files and byte slices
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
	// KeySize is the size of Curve25519 private and public keys in bytes.
	// Both private and public keys are always 32 bytes (256 bits) in X25519.
	KeySize = 32
)

var (
	// ErrInvalidKeySize is returned when a decoded key does not have
	// the expected length of KeySize (32 bytes).
	ErrInvalidKeySize = errors.New("invalid key size")

	// ErrInvalidKeyPair is returned when a key pair fails validation.
	ErrInvalidKeyPair = errors.New("invalid key pair")

	// ErrInvalidEncoding is returned when an unrecognized encoding type
	// is specified for serialization or deserialization operations.
	ErrInvalidEncoding = errors.New("invalid encoding format")
)

// KeyPair represents a Curve25519 ECDH key pair consisting of a private key
// and its corresponding public key. Both keys are fixed-size 32-byte arrays.
type KeyPair struct {
	// PrivateKey is the 32-byte secret key used for ECDH scalar multiplication.
	// It must be kept confidential and never transmitted.
	PrivateKey [KeySize]byte

	// PublicKey is the 32-byte public key derived from the private key via
	// scalar multiplication with the standard Curve25519 base point. It can
	// be freely shared with other parties.
	PublicKey [KeySize]byte
}

// GenerateKeyPair generates a new cryptographically secure Curve25519 key pair.
//
// The private key is generated using crypto/rand, which reads from the
// system's cryptographically secure random number generator. The public key
// is derived by performing scalar multiplication of the private key with
// the standard Curve25519 base point.
//
// Returns a pointer to the new KeyPair on success, or nil with an error
// if the random number generation fails.
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte
	var publicKey [KeySize]byte

	// Read 32 bytes of cryptographically secure random data to serve as
	// the private key scalar. The curve25519 library applies clamping
	// internally during ScalarBaseMult.
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Compute the public key: publicKey = privateKey * BasePoint
	// ScalarBaseMult also applies X25519 key clamping to the private key,
	// clearing the low 3 bits and setting high bits per RFC 7748.
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// GenerateKeyPairFromReader generates a Curve25519 key pair using randomness
// read from a custom io.Reader.
//
// This function is primarily useful for testing with deterministic randomness,
// or when you want to source key material from a custom entropy source.
// For production use, prefer GenerateKeyPair which uses crypto/rand.
//
// Parameters:
//   - r: an io.Reader that provides at least KeySize (32) bytes of key material.
//
// Returns a pointer to the new KeyPair on success, or nil with an error
// if the reader fails to provide enough data.
func GenerateKeyPairFromReader(r io.Reader) (*KeyPair, error) {
	var privateKey [KeySize]byte
	var publicKey [KeySize]byte

	// Read exactly KeySize bytes from the provided reader to use as
	// the private key scalar. io.ReadFull ensures we get all 32 bytes.
	_, err := io.ReadFull(r, privateKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Derive the public key via scalar multiplication with the base point.
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// ComputeSharedSecret computes an ECDH shared secret between a local private
// key and a remote party's public key using the X25519 function.
//
// The shared secret is computed as: sharedSecret = privateKey * peerPublicKey
// This is the core Diffie-Hellman operation that allows two parties to
// independently arrive at the same shared secret using their own private key
// and the other party's public key.
//
// Parameters:
//   - privateKey: the local party's 32-byte private key.
//   - publicKey: the remote party's 32-byte public key.
//
// Returns the 32-byte shared secret on success. Returns an error if the
// computed shared secret is all zeros, which indicates the peer's public
// key is invalid (e.g., a low-order point).
func ComputeSharedSecret(privateKey [KeySize]byte, publicKey [KeySize]byte) ([KeySize]byte, error) {
	var sharedSecret [KeySize]byte

	// Perform X25519 scalar multiplication: shared = privateKey * publicKey
	// This is the core ECDH operation defined in RFC 7748.
	curve25519.ScalarMult(&sharedSecret, &privateKey, &publicKey)

	// Security check: an all-zero shared secret indicates the peer public
	// key is a low-order point on the curve, which would result in a
	// predictable shared secret. Reject such keys per RFC 7748 guidance.
	var zero [KeySize]byte
	if sharedSecret == zero {
		return zero, errors.New("invalid public key: resulted in zero shared secret")
	}

	return sharedSecret, nil
}

// ComputeSharedSecret computes an ECDH shared secret between this key pair's
// private key and a peer's public key.
//
// This is a convenience method on KeyPair that delegates to the package-level
// ComputeSharedSecret function.
//
// Parameters:
//   - peerPublicKey: the remote party's 32-byte Curve25519 public key.
//
// Returns the 32-byte shared secret on success, or an error if the peer's
// public key produces an all-zero shared secret.
func (kp *KeyPair) ComputeSharedSecret(peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	return ComputeSharedSecret(kp.PrivateKey, peerPublicKey)
}

// EncodingType defines the text encoding format used for serializing
// and deserializing keys.
type EncodingType int

const (
	// EncodingHex represents hexadecimal (base16) encoding. Each byte is
	// represented by two hex characters, producing 64 characters for
	// a 32-byte key.
	EncodingHex EncodingType = iota

	// EncodingBase64 represents standard base64 encoding as defined in
	// RFC 4648. Uses '+' and '/' characters and may include '=' padding.
	EncodingBase64

	// EncodingBase64URL represents URL-safe base64 encoding as defined in
	// RFC 4648. Uses '-' and '_' characters instead of '+' and '/'.
	EncodingBase64URL
)

// SerializePrivateKey encodes a 32-byte Curve25519 private key into a string
// using the specified encoding format.
//
// Parameters:
//   - key: the 32-byte private key to serialize.
//   - encoding: the encoding format to use (EncodingHex, EncodingBase64,
//     or EncodingBase64URL). If an unrecognized value is provided,
//     EncodingHex is used as the default.
//
// Returns the encoded key string.
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

// SerializePublicKey encodes a 32-byte Curve25519 public key into a string
// using the specified encoding format.
//
// Since public and private keys have the same size and structure, this
// function delegates to SerializePrivateKey.
//
// Parameters:
//   - key: the 32-byte public key to serialize.
//   - encoding: the encoding format to use.
//
// Returns the encoded key string.
func SerializePublicKey(key [KeySize]byte, encoding EncodingType) string {
	return SerializePrivateKey(key, encoding)
}

// DeserializePrivateKey decodes a Curve25519 private key from a string using
// the specified encoding format.
//
// Parameters:
//   - data: the encoded key string.
//   - encoding: the encoding format (EncodingHex, EncodingBase64, or
//     EncodingBase64URL). If an unrecognized value is provided,
//     EncodingHex is used as the default.
//
// Returns the 32-byte decoded key on success. Returns an error if the
// string cannot be decoded or if the decoded data is not exactly KeySize
// (32) bytes long.
func DeserializePrivateKey(data string, encoding EncodingType) ([KeySize]byte, error) {
	var key [KeySize]byte
	var decoded []byte
	var err error

	// Decode the input string according to the specified encoding.
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

	// Validate that the decoded data has the correct key size.
	// Curve25519 keys must be exactly 32 bytes.
	if len(decoded) != KeySize {
		return key, ErrInvalidKeySize
	}

	copy(key[:], decoded)
	return key, nil
}

// DeserializePublicKey decodes a Curve25519 public key from a string using
// the specified encoding format.
//
// Since public and private keys have the same size and structure, this
// function delegates to DeserializePrivateKey.
//
// Parameters:
//   - data: the encoded key string.
//   - encoding: the encoding format to use.
//
// Returns the 32-byte decoded key on success, or an error on failure.
func DeserializePublicKey(data string, encoding EncodingType) ([KeySize]byte, error) {
	return DeserializePrivateKey(data, encoding)
}

// SerializeKeyPair serializes both the private and public keys from a KeyPair
// into string format using the specified encoding.
//
// Parameters:
//   - kp: the key pair to serialize.
//   - encoding: the encoding format to use for both keys.
//
// Returns two strings: the encoded private key followed by the encoded
// public key.
func SerializeKeyPair(kp *KeyPair, encoding EncodingType) (privateKey, publicKey string) {
	return SerializePrivateKey(kp.PrivateKey, encoding), SerializePublicKey(kp.PublicKey, encoding)
}

// DeserializeKeyPair reconstructs a KeyPair from separately encoded private
// and public key strings.
//
// Parameters:
//   - privateKeyStr: the encoded private key string.
//   - publicKeyStr: the encoded public key string.
//   - encoding: the encoding format used for both strings.
//
// Returns a pointer to the reconstructed KeyPair on success, or nil with
// an error if either key fails to decode.
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

// SaveKeyPairToFile writes a key pair to a file in a two-line text format.
//
// File format:
//   - First line: encoded private key
//   - Second line: encoded public key
//
// The file is created with default permissions. If the file already exists,
// it will be truncated and overwritten.
//
// Parameters:
//   - kp: the key pair to save.
//   - filename: the path to the output file.
//   - encoding: the encoding format for the keys.
//
// Returns nil on success, or an error if file creation or writing fails.
func SaveKeyPairToFile(kp *KeyPair, filename string, encoding EncodingType) error {
	privateKeyStr, publicKeyStr := SerializeKeyPair(kp, encoding)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	// Write the private key as the first line of the file.
	_, err = fmt.Fprintln(file, privateKeyStr)
	if err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write the public key as the second line of the file.
	_, err = fmt.Fprintln(file, publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadKeyPairFromFile reads a key pair from a file in the two-line text
// format produced by SaveKeyPairToFile.
//
// Expected file format:
//   - First line: encoded private key
//   - Second line: encoded public key
//
// Parameters:
//   - filename: the path to the input file.
//   - encoding: the encoding format used for the keys in the file.
//
// Returns a pointer to the loaded KeyPair on success, or nil with an error
// if the file cannot be opened, read, or parsed.
func LoadKeyPairFromFile(filename string, encoding EncodingType) (*KeyPair, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %w", err)
	}
	defer file.Close()

	var privateKeyStr, publicKeyStr string

	// Read the private key from the first line of the file.
	_, err = fmt.Fscanln(file, &privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Read the public key from the second line of the file.
	_, err = fmt.Fscanln(file, &publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return DeserializeKeyPair(privateKeyStr, publicKeyStr, encoding)
}

// LoadKeyPairFromBytes parses a key pair from a byte slice in the two-line
// text format produced by SaveKeyPairToFile.
//
// Expected data format:
//   - First line: encoded private key
//   - Second line: encoded public key
//
// Leading and trailing whitespace on each line is trimmed before parsing.
//
// Parameters:
//   - data: the byte slice containing the two-line key data.
//   - encoding: the encoding format used for the keys.
//
// Returns a pointer to the parsed KeyPair on success, or nil with an error
// if the data cannot be parsed.
func LoadKeyPairFromBytes(data []byte, encoding EncodingType) (*KeyPair, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var privateKeyStr, publicKeyStr string

	// Parse the private key from the first line of the input data.
	// Trim whitespace to be tolerant of extra spaces or newlines.
	if scanner.Scan() {
		privateKeyStr = strings.TrimSpace(scanner.Text())
	} else {
		return nil, fmt.Errorf("failed to read private key: no data")
	}

	// Parse the public key from the second line of the input data.
	if scanner.Scan() {
		publicKeyStr = strings.TrimSpace(scanner.Text())
	} else {
		return nil, fmt.Errorf("failed to read public key: no data")
	}

	// Check for any error that occurred during scanning.
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan key data: %w", err)
	}

	return DeserializeKeyPair(privateKeyStr, publicKeyStr, encoding)
}

// SavePublicKeyToFile writes a single public key to a file as a single line
// of encoded text.
//
// Parameters:
//   - publicKey: the 32-byte public key to save.
//   - filename: the path to the output file.
//   - encoding: the encoding format for the key.
//
// Returns nil on success, or an error if file creation or writing fails.
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

// LoadPublicKeyFromFile reads a single public key from a file containing
// one line of encoded text.
//
// Parameters:
//   - filename: the path to the input file.
//   - encoding: the encoding format used for the key.
//
// Returns the 32-byte public key on success, or a zero-value key with an
// error if the file cannot be opened, read, or parsed.
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

// LoadPublicKeyFromBytes parses a single public key from a byte slice
// containing encoded text.
//
// Leading and trailing whitespace is trimmed before parsing, making this
// function tolerant of extra newlines or spaces.
//
// Parameters:
//   - data: the byte slice containing the encoded public key.
//   - encoding: the encoding format used for the key.
//
// Returns the 32-byte public key on success, or a zero-value key with an
// error if parsing fails.
func LoadPublicKeyFromBytes(data []byte, encoding EncodingType) ([KeySize]byte, error) {
	publicKeyStr := strings.TrimSpace(string(data))
	return DeserializePublicKey(publicKeyStr, encoding)
}

// String returns a human-readable string representation of the key pair.
//
// For security reasons, the private key is always redacted and never
// included in the output. The public key is shown in hexadecimal format.
// This method implements the fmt.Stringer interface.
//
// Returns a string in the format: KeyPair{PublicKey: <hex>, PrivateKey: [REDACTED]}
func (kp *KeyPair) String() string {
	return fmt.Sprintf("KeyPair{PublicKey: %s, PrivateKey: [REDACTED]}",
		SerializePublicKey(kp.PublicKey, EncodingHex))
}

// SafeString returns a fully redacted string representation of the key pair.
//
// Both the public key and private key are redacted. This is useful for
// logging or error messages where even the public key should not be
// exposed for privacy or operational security reasons.
//
// Returns: "KeyPair{PublicKey: [REDACTED], PrivateKey: [REDACTED]}"
func (kp *KeyPair) SafeString() string {
	return "KeyPair{PublicKey: [REDACTED], PrivateKey: [REDACTED]}"
}
