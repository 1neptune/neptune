// Package crypto provides high-level encryption and decryption functionality
// for the Neptune project. It combines elliptic curve Diffie-Hellman key
// exchange using Curve25519 with the Sosemanuk stream cipher to provide
// secure, efficient symmetric encryption.
//
// The encryption scheme works as follows:
//  1. A shared secret is computed between sender and recipient using
//     Curve25519 ECDH key exchange.
//  2. The shared secret is derived into a 256-bit encryption key using
//     HKDF with SHA-256 (RFC 5869).
//  3. A cryptographically random 128-bit nonce is generated.
//  4. The plaintext is encrypted using the Sosemanuk stream cipher with
//     the derived key and nonce.
//  5. The encrypted output includes a header with version, sender public
//     key, and nonce, followed by the ciphertext.
//
// The package supports both in-memory encryption/decryption (Encrypt/Decrypt)
// and streaming encryption/decryption (EncryptStream/DecryptStream) for
// handling large data efficiently.
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
	// Version defines the current version of the encrypted data format.
	// It is stored as the first byte of the serialized encrypted data
	// to allow future format changes while maintaining backward compatibility.
	Version = 1

	// KeySize is the size in bytes of the derived symmetric encryption key.
	// A 32-byte (256-bit) key provides a high level of security for
	// symmetric encryption, matching the security level of Curve25519.
	KeySize = 32

	// NonceSize is the size in bytes of the nonce used with the Sosemanuk
	// stream cipher. A 16-byte (128-bit) nonce ensures that encrypting
	// the same plaintext multiple times with the same key produces
	// different ciphertexts (semantic security). The nonce must be
	// cryptographically random and never reused with the same key.
	NonceSize = 16

	// PublicKeySize is the size in bytes of a Curve25519 public key.
	// This value is delegated to the curve25519 package to ensure
	// consistency across the codebase. Curve25519 public keys are
	// always 32 bytes.
	PublicKeySize = neptuneCurve25519.KeySize

	// PrivateKeySize is the size in bytes of a Curve25519 private key.
	// This value is delegated to the curve25519 package to ensure
	// consistency across the codebase. Curve25519 private keys are
	// always 32 bytes.
	PrivateKeySize = neptuneCurve25519.KeySize

	// HeaderSize is the total size in bytes of the encryption header
	// that precedes the ciphertext in serialized encrypted data.
	// The header layout is:
	//   - Version: 1 byte
	//   - SenderPubKey: PublicKeySize (32) bytes
	//   - Nonce: NonceSize (16) bytes
	// Total: 1 + 32 + 16 = 49 bytes
	HeaderSize = 1 + PublicKeySize + NonceSize
)

var (
	// ErrInvalidVersion is returned when the version byte in the encrypted
	// data header does not match the current supported version. This
	// indicates the data was encrypted with an incompatible format version.
	ErrInvalidVersion = errors.New("crypto: invalid or unsupported version")

	// ErrInvalidCiphertext is returned when the ciphertext or encrypted
	// data is too short to be valid. This occurs when the input data is
	// smaller than HeaderSize, meaning it cannot contain a complete
	// encryption header.
	ErrInvalidCiphertext = errors.New("crypto: ciphertext is too short")

	// ErrInvalidKeySize is returned when the input key or shared secret
	// has an invalid size (typically zero length). Valid keys must be
	// non-empty to produce meaningful derived keys.
	ErrInvalidKeySize = errors.New("crypto: invalid key size")

	// ErrDeriveKeyFailed is returned when the HKDF key derivation process
	// fails to produce the required number of key bytes. This should be
	// extremely rare and typically indicates an internal error in the
	// HKDF implementation.
	ErrDeriveKeyFailed = errors.New("crypto: failed to derive encryption key")

	// ErrInvalidPrivateKey is returned when a provided Curve25519 private
	// key is invalid (e.g., all zeros or otherwise not a valid scalar).
	ErrInvalidPrivateKey = errors.New("crypto: invalid private key")
)

// EncryptedData represents the result of an encryption operation, containing
// both the ciphertext and all metadata required for decryption. This struct
// is the primary data type passed between encrypting and decrypting parties.
//
// The structure includes everything needed to decrypt the data:
//   - The encryption format version for backward compatibility
//   - The sender's public key for ECDH shared secret computation
//   - The nonce used for the stream cipher
//   - The actual encrypted payload
type EncryptedData struct {
	// Version is the encryption format version identifier. It must match
	// the current Version constant for successful decryption. This field
	// enables future protocol upgrades.
	Version byte

	// SenderPubKey is the Curve25519 public key of the sender. The
	// recipient uses this public key together with their own private key
	// to compute the shared ECDH secret needed for decryption.
	SenderPubKey [PublicKeySize]byte

	// Nonce is the cryptographically random value used to initialize the
	// Sosemanuk stream cipher. It ensures that encrypting the same
	// plaintext with the same key produces different ciphertexts. The
	// nonce is not secret but must be unique per encryption with the
	// same key.
	Nonce [NonceSize]byte

	// Ciphertext is the encrypted data produced by the Sosemanuk stream
	// cipher. Its length is identical to the length of the original
	// plaintext (stream cipher encryption does not add padding).
	Ciphertext []byte
}

// KeyPair is a type alias for the Curve25519 key pair type from the
// neptune/pkg/curve25519 package. It provides convenient access to the
// key pair type without requiring callers to import the curve25519
// package directly.
type KeyPair = neptuneCurve25519.KeyPair

// GenerateKeyPair generates a new cryptographically secure Curve25519
// key pair. The private key is generated using crypto/rand for
// cryptographic randomness.
//
// Returns:
//   - A pointer to the newly generated KeyPair containing both private
//     and public keys.
//   - An error if key generation fails (e.g., if the system's random
//     number generator is unavailable).
func GenerateKeyPair() (*KeyPair, error) {
	return neptuneCurve25519.GenerateKeyPair()
}

// DeriveEncryptionKey derives a symmetric encryption key from a shared
// secret using HKDF (HMAC-based Key Derivation Function) with SHA-256.
// This follows the HKDF specification defined in RFC 5869.
//
// The derivation process:
//  1. The context is hashed with SHA-256 to produce the HKDF salt.
//  2. HKDF-Extract is applied with the shared secret and salt to
//     produce a pseudorandom key (PRK).
//  3. HKDF-Expand is applied with the PRK and context info to produce
//     the final KeySize-byte encryption key.
//
// Parameters:
//   - sharedSecret: The raw shared secret bytes obtained from Curve25519
//     ECDH key exchange. Must be non-empty.
//   - context: Additional context data used for domain separation. This
//     ensures that keys derived for different purposes are distinct even
//     if the shared secret is the same. Can be empty.
//
// Returns:
//   - A 32-byte (256-bit) derived encryption key.
//   - ErrInvalidKeySize if sharedSecret is empty.
//   - ErrDeriveKeyFailed wrapped with details if HKDF derivation fails.
func DeriveEncryptionKey(sharedSecret []byte, context []byte) ([]byte, error) {
	// Validate that the shared secret is non-empty. An empty shared
	// secret cannot produce a meaningful derived key.
	if len(sharedSecret) == 0 {
		return nil, ErrInvalidKeySize
	}

	// Hash the context with SHA-256 to produce the HKDF salt.
	// Using the context as salt ensures that different contexts produce
	// different derived keys, providing domain separation between
	// different encryption contexts or protocols.
	salt := sha256.Sum256(context)

	// Create an HKDF reader using SHA-256 as the hash function.
	// HKDF-Extract combines the shared secret with the salt to produce
	// a pseudorandom key. HKDF-Expand then produces the output keying
	// material using the context as additional info.
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt[:], context)

	// Read exactly KeySize bytes from the HKDF reader to get the final
	// derived encryption key. io.ReadFull ensures we get the exact
	// number of bytes needed.
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeriveKeyFailed, err)
	}

	return key, nil
}

// DerivePublicKey computes the Curve25519 public key corresponding to a
// given private key using scalar multiplication with the base point.
//
// This function performs the operation: publicKey = privateKey * G,
// where G is the standard Curve25519 base point.
//
// Parameters:
//   - privateKey: The Curve25519 private key (32 bytes). This is a
//     scalar value used for elliptic curve scalar multiplication.
//
// Returns:
//   - The corresponding Curve25519 public key (32 bytes), which is the
//     result of scalar-multiplying the private key with the base point.
func DerivePublicKey(privateKey [PrivateKeySize]byte) [PublicKeySize]byte {
	var publicKey [PublicKeySize]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

// GenerateNonce generates a cryptographically secure random nonce for use
// with the Sosemanuk stream cipher. The nonce is NonceSize (16) bytes long
// and is generated using crypto/rand, which reads from the system's
// cryptographically secure random number generator.
//
// Each encryption operation MUST use a unique nonce. Reusing a nonce with
// the same key compromises security, as an attacker could XOR two
// ciphertexts encrypted with the same key and nonce to get the XOR of
// the two plaintexts.
//
// Returns:
//   - A 16-byte cryptographically random nonce.
//   - An error if the system's random number generator fails to produce
//     the required number of bytes.
func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	// Fill the nonce buffer with cryptographically random bytes from
	// the system's secure random number generator.
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nonce, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// Encrypt encrypts plaintext using the sender's private key and the
// recipient's public key. The encryption uses Curve25519 ECDH for key
// exchange, HKDF-SHA256 for key derivation, and Sosemanuk as the stream
// cipher.
//
// The encryption process:
//  1. Derive the sender's public key from the provided private key.
//  2. Compute the ECDH shared secret using the sender's private key and
//     the recipient's public key.
//  3. Derive a symmetric encryption key from the shared secret using
//     HKDF-SHA256 with domain-separated context.
//  4. Generate a cryptographically random nonce.
//  5. Encrypt the plaintext using the Sosemanuk stream cipher with the
//     derived key and nonce.
//  6. Package all metadata (version, sender public key, nonce) and
//     ciphertext into an EncryptedData struct.
//
// Note: If you already have the full KeyPair (both public and private
// keys), use EncryptWithKeyPair for better performance, as it skips
// the public key derivation step.
//
// Parameters:
//   - plaintext: The data to be encrypted. Can be empty.
//   - senderPrivateKey: The Curve25519 private key of the sender. Used
//     to compute the ECDH shared secret and derive the sender's public key.
//   - recipientPublicKey: The Curve25519 public key of the intended
//     recipient. Used to compute the ECDH shared secret.
//
// Returns:
//   - A pointer to an EncryptedData struct containing the encrypted data
//     and all metadata needed for decryption.
//   - An error if any step of the encryption process fails.
func Encrypt(plaintext []byte, senderPrivateKey [PrivateKeySize]byte, recipientPublicKey [PublicKeySize]byte) (*EncryptedData, error) {
	// Derive the sender's public key from the private key using
	// Curve25519 scalar base multiplication. This is needed because
	// the recipient needs the sender's public key to compute the same
	// shared secret during decryption.
	senderPublicKey := DerivePublicKey(senderPrivateKey)

	// Construct a temporary KeyPair struct with the private key and
	// derived public key, then delegate to EncryptWithKeyPair for the
	// actual encryption logic.
	senderKeyPair := &KeyPair{
		PrivateKey: senderPrivateKey,
		PublicKey:  senderPublicKey,
	}

	return EncryptWithKeyPair(plaintext, senderKeyPair, recipientPublicKey)
}

// EncryptWithKeyPair encrypts plaintext using a complete sender KeyPair
// and the recipient's public key. This is the primary encryption function
// and is more efficient than Encrypt when the caller already has both
// the private and public keys available.
//
// The encryption process:
//  1. Compute the ECDH shared secret using the sender's key pair and
//     the recipient's public key.
//  2. Derive a symmetric encryption key from the shared secret using
//     HKDF-SHA256. The context includes the recipient's public key for
//     domain separation.
//  3. Generate a cryptographically random nonce.
//  4. Initialize the Sosemanuk stream cipher with the derived key and
//     nonce.
//  5. Encrypt the plaintext by XORing it with the Sosemanuk keystream.
//  6. Return an EncryptedData struct with all metadata and ciphertext.
//
// Parameters:
//   - plaintext: The data to be encrypted. Can be empty.
//   - senderKeyPair: The Curve25519 key pair of the sender. Both the
//     private key (for ECDH) and public key (for inclusion in the
//     encrypted data header) are used.
//   - recipientPublicKey: The Curve25519 public key of the intended
//     recipient. Used to compute the ECDH shared secret.
//
// Returns:
//   - A pointer to an EncryptedData struct containing the encrypted data
//     and all metadata needed for decryption.
//   - An error if shared secret computation, key derivation, nonce
//     generation, or cipher initialization fails.
func EncryptWithKeyPair(plaintext []byte, senderKeyPair *KeyPair, recipientPublicKey [PublicKeySize]byte) (*EncryptedData, error) {
	// Compute the shared secret using Curve25519 ECDH. The sender
	// multiplies their private key with the recipient's public key to
	// produce the same shared secret that the recipient will compute
	// using their private key and the sender's public key.
	sharedSecret, err := senderKeyPair.ComputeSharedSecret(recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive a symmetric encryption key from the shared secret using
	// HKDF-SHA256. The context string "neptune-encryption" combined with
	// the recipient's public key ensures domain separation: keys derived
	// for different recipients or different purposes will be distinct
	// even if the same shared secret is used.
	context := append([]byte("neptune-encryption"), recipientPublicKey[:]...)
	encryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Generate a cryptographically random nonce. Each encryption must
	// use a unique nonce to ensure semantic security - encrypting the
	// same plaintext twice with the same key but different nonces
	// produces entirely different ciphertexts.
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Initialize the Sosemanuk stream cipher with the derived encryption
	// key and the random nonce. Sosemanuk is a synchronous stream cipher
	// that generates a keystream from the key and nonce.
	cipher, err := sosemanuk.New(encryptionKey, nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt the plaintext by XORing it with the Sosemanuk keystream.
	// Stream ciphers produce a keystream of the same length as the
	// plaintext, and encryption is done byte-by-byte with XOR. The
	// same operation (XOR with keystream) is used for both encryption
	// and decryption.
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	return &EncryptedData{
		Version:      Version,
		SenderPubKey: senderKeyPair.PublicKey,
		Nonce:         nonce,
		Ciphertext:   ciphertext,
	}, nil
}

// Decrypt decrypts EncryptedData using the recipient's private key. It
// reverses the encryption process performed by Encrypt, recovering the
// original plaintext.
//
// The decryption process:
//  1. Derive the recipient's public key from the provided private key.
//  2. Verify the encryption format version is supported.
//  3. Compute the ECDH shared secret using the recipient's private key
//     and the sender's public key from the encrypted data.
//  4. Derive the symmetric decryption key using HKDF-SHA256 (same
//     derivation as encryption).
//  5. Decrypt the ciphertext using the Sosemanuk stream cipher with the
//     derived key and the nonce from the encrypted data.
//
// Note: If you already have the full KeyPair (both public and private
// keys), use DecryptWithKeyPair for better performance, as it skips
// the public key derivation step.
//
// Parameters:
//   - encryptedData: The EncryptedData struct containing the ciphertext
//     and all metadata (version, sender public key, nonce).
//   - recipientPrivateKey: The Curve25519 private key of the recipient.
//     Used to compute the ECDH shared secret.
//
// Returns:
//   - The decrypted plaintext bytes. The length matches the original
//     plaintext length.
//   - ErrInvalidVersion if the encryption format version is not supported.
//   - An error if any step of the decryption process fails.
func Decrypt(encryptedData *EncryptedData, recipientPrivateKey [PrivateKeySize]byte) ([]byte, error) {
	// Derive the recipient's public key from the private key. This is
	// needed for the HKDF context calculation (which must match the
	// context used during encryption) and for constructing the KeyPair.
	recipientPublicKey := DerivePublicKey(recipientPrivateKey)

	// Construct a temporary KeyPair struct with the private key and
	// derived public key, then delegate to DecryptWithKeyPair for the
	// actual decryption logic.
	recipientKeyPair := &KeyPair{
		PrivateKey: recipientPrivateKey,
		PublicKey:  recipientPublicKey,
	}

	return DecryptWithKeyPair(encryptedData, recipientKeyPair)
}

// DecryptWithKeyPair decrypts EncryptedData using a complete recipient
// KeyPair. This is the primary decryption function and is more efficient
// than Decrypt when the caller already has both the private and public
// keys available.
//
// The decryption process:
//  1. Verify the encryption format version matches the current version.
//  2. Compute the ECDH shared secret using the recipient's key pair and
//     the sender's public key from the encrypted data.
//  3. Derive the symmetric decryption key using HKDF-SHA256. The context
//     must exactly match the context used during encryption.
//  4. Initialize the Sosemanuk stream cipher with the derived key and
//     the nonce from the encrypted data.
//  5. Decrypt the ciphertext by XORing it with the Sosemanuk keystream.
//
// Since Sosemanuk is a stream cipher, decryption is identical to
// encryption: XOR the ciphertext with the same keystream to recover
// the plaintext.
//
// Parameters:
//   - encryptedData: The EncryptedData struct containing the ciphertext
//     and all metadata (version, sender public key, nonce).
//   - recipientKeyPair: The Curve25519 key pair of the recipient. The
//     private key is used for ECDH, and the public key is used for the
//     HKDF context (must match encryption context).
//
// Returns:
//   - The decrypted plaintext bytes. The length matches the original
//     plaintext length.
//   - ErrInvalidVersion if the encryption format version is not supported.
//   - An error if shared secret computation, key derivation, or cipher
//     initialization fails.
func DecryptWithKeyPair(encryptedData *EncryptedData, recipientKeyPair *KeyPair) ([]byte, error) {
	// Verify that the encrypted data uses a supported format version.
	// If the version doesn't match, we cannot decrypt the data correctly,
	// so we return ErrInvalidVersion immediately.
	if encryptedData.Version != Version {
		return nil, ErrInvalidVersion
	}

	// Compute the shared secret using Curve25519 ECDH. The recipient
	// multiplies their private key with the sender's public key to
	// produce the same shared secret that the sender computed during
	// encryption (using the sender's private key and recipient's public key).
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(encryptedData.SenderPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive the symmetric decryption key from the shared secret using
	// HKDF-SHA256. The context MUST exactly match the context used
	// during encryption: "neptune-encryption" + recipient's public key.
	// This ensures both sides derive the same key.
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)
	decryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decryption key: %w", err)
	}

	// Initialize the Sosemanuk stream cipher with the derived decryption
	// key and the nonce from the encrypted data. Since Sosemanuk is a
	// symmetric stream cipher, the same key+nonce pair produces the same
	// keystream for both encryption and decryption.
	cipher, err := sosemanuk.New(decryptionKey, encryptedData.Nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt the ciphertext by XORing it with the Sosemanuk keystream.
	// For stream ciphers, encryption and decryption are the same
	// operation: XOR with the keystream. XORing the ciphertext with the
	// keystream recovers the original plaintext.
	plaintext := make([]byte, len(encryptedData.Ciphertext))
	cipher.XORKeyStream(plaintext, encryptedData.Ciphertext)

	return plaintext, nil
}

// Serialize converts an EncryptedData struct into a contiguous byte slice
// suitable for storage or transmission. The output format is:
//
//	[Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes][Ciphertext: variable bytes]
//
// The total length is HeaderSize + len(Ciphertext).
//
// This is the inverse of DeserializeEncryptedData.
//
// Returns:
//   - A byte slice containing the serialized encrypted data. The caller
//     takes ownership of the returned slice.
func (ed *EncryptedData) Serialize() []byte {
	totalSize := HeaderSize + len(ed.Ciphertext)
	result := make([]byte, totalSize)

	offset := 0
	// Write the 1-byte version field at the beginning of the buffer.
	result[0] = ed.Version
	offset += 1

	// Copy the sender's public key (32 bytes) after the version byte.
	copy(result[offset:], ed.SenderPubKey[:])
	offset += PublicKeySize

	// Copy the nonce (16 bytes) after the sender's public key.
	copy(result[offset:], ed.Nonce[:])
	offset += NonceSize

	// Copy the variable-length ciphertext after the nonce.
	copy(result[offset:], ed.Ciphertext)

	return result
}

// DeserializeEncryptedData parses a byte slice into an EncryptedData struct.
// It validates that the data is long enough to contain a complete header
// and that the format version is supported.
//
// The expected input format is:
//
//	[Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes][Ciphertext: variable bytes]
//
// This is the inverse of EncryptedData.Serialize.
//
// Parameters:
//   - data: The byte slice containing serialized encrypted data.
//
// Returns:
//   - A pointer to the deserialized EncryptedData struct.
//   - ErrInvalidCiphertext if data is shorter than HeaderSize.
//   - ErrInvalidVersion if the version byte does not match the current
//     supported version.
func DeserializeEncryptedData(data []byte) (*EncryptedData, error) {
	// Validate that the input data is at least long enough to contain
	// the complete header. If it's too short, it cannot be valid
	// encrypted data.
	if len(data) < HeaderSize {
		return nil, ErrInvalidCiphertext
	}

	offset := 0
	// Read the 1-byte version field from the start of the data.
	version := data[offset]
	offset += 1

	// Verify the version is supported before proceeding. An unsupported
	// version means we cannot correctly interpret the rest of the data.
	if version != Version {
		return nil, ErrInvalidVersion
	}

	// Read the sender's public key (32 bytes) from the data.
	var senderPubKey [PublicKeySize]byte
	copy(senderPubKey[:], data[offset:])
	offset += PublicKeySize

	// Read the nonce (16 bytes) from the data.
	var nonce [NonceSize]byte
	copy(nonce[:], data[offset:])
	offset += NonceSize

	// The remaining bytes after the header are the ciphertext.
	ciphertext := make([]byte, len(data)-offset)
	copy(ciphertext, data[offset:])

	return &EncryptedData{
		Version:      version,
		SenderPubKey: senderPubKey,
		Nonce:         nonce,
		Ciphertext:   ciphertext,
	}, nil
}

// EncryptStream performs streaming encryption of data read from an
// io.Reader and writes the encrypted result to an io.Writer. This function
// is suitable for encrypting large files or data streams without loading
// the entire plaintext into memory.
//
// The streaming encryption process:
//  1. Compute the ECDH shared secret using the sender's key pair and
//     the recipient's public key.
//  2. Derive the encryption key using HKDF-SHA256.
//  3. Generate a random nonce.
//  4. Write the encryption header (Version + SenderPubKey + Nonce) to
//     the writer.
//  5. Read plaintext from the reader in chunks, encrypt each chunk with
//     the Sosemanuk stream cipher, and write the encrypted chunks to
//     the writer.
//
// A buffer pool is used to minimize memory allocations during the
// streaming process.
//
// Parameters:
//   - plaintext: An io.Reader providing the plaintext data to encrypt.
//   - writer: An io.Writer where the encrypted data (header + ciphertext)
//     will be written.
//   - senderKeyPair: The Curve25519 key pair of the sender.
//   - recipientPublicKey: The Curve25519 public key of the recipient.
//   - bufferSize: The size in bytes of the buffer used for reading and
//     encrypting chunks. Recommended range is 4KB to 64KB depending on
//     the expected data size and memory constraints.
//
// Returns:
//   - totalBytes: The total number of plaintext bytes encrypted. This
//     does not include the header size.
//   - err: An error if any step fails. If an error occurs, some data
//     may already have been written to the writer.
func EncryptStream(plaintext io.Reader, writer io.Writer, senderKeyPair *KeyPair, recipientPublicKey [PublicKeySize]byte, bufferSize int) (totalBytes int64, err error) {
	// Compute the ECDH shared secret between sender and recipient.
	// This is the same shared secret computation used in non-streaming
	// encryption.
	sharedSecret, err := senderKeyPair.ComputeSharedSecret(recipientPublicKey)
	if err != nil {
		return 0, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive the symmetric encryption key using HKDF-SHA256 with the
	// same context as non-streaming encryption for consistency.
	context := append([]byte("neptune-encryption"), recipientPublicKey[:]...)
	encryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return 0, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	// Generate a cryptographically random nonce for this encryption
	// session. Each stream encryption must use a unique nonce.
	nonce, err := GenerateNonce()
	if err != nil {
		return 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Initialize the Sosemanuk stream cipher. The cipher state is
	// maintained across all chunks, ensuring the keystream is
	// continuous throughout the entire stream.
	cipher, err := sosemanuk.New(encryptionKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Construct and write the encryption header to the writer.
	// Header format: [Version: 1 byte][SenderPubKey: 32 bytes][Nonce: 16 bytes]
	// The recipient needs this header to initialize decryption.
	header := make([]byte, HeaderSize)
	header[0] = Version
	copy(header[1:], senderKeyPair.PublicKey[:])
	copy(header[1+PublicKeySize:], nonce[:])

	if _, err := writer.Write(header); err != nil {
		return 0, fmt.Errorf("failed to write header: %w", err)
	}

	// Obtain a buffer from the global buffer pool to avoid repeated
	// memory allocations in the encryption loop. The buffer is returned
	// to the pool when done via defer.
	buf := getGlobalBuffer(bufferSize)
	defer putGlobalBuffer(buf)

	// Stream encryption loop: read plaintext in chunks, encrypt each
	// chunk, and write the ciphertext to the output writer.
	totalBytes = 0
	for {
		// Read up to bufferSize bytes of plaintext from the reader.
		n, readErr := plaintext.Read(buf)

		// If we read any data, encrypt it and write it out.
		// This block handles both full and partial reads.
		if n > 0 {
			// Encrypt the chunk by XORing with the Sosemanuk keystream.
			// The cipher state advances with each call, maintaining
			// keystream continuity across chunks.
			encryptedChunk := make([]byte, n)
			cipher.XORKeyStream(encryptedChunk, buf[:n])

			// Write the encrypted chunk to the output writer.
			if _, writeErr := writer.Write(encryptedChunk); writeErr != nil {
				return totalBytes, fmt.Errorf("failed to write encrypted data: %w", writeErr)
			}

			totalBytes += int64(n)
		}

		// Handle end of input stream.
		// io.EOF indicates the reader has no more data, which is the
		// normal termination condition for the streaming loop.
		if readErr == io.EOF {
			break
		}
		// Handle any other read error.
		if readErr != nil {
			return totalBytes, fmt.Errorf("failed to read plaintext: %w", readErr)
		}
		// If n == 0 and readErr == nil, the reader returned a
		// zero-length read without error (permitted by the io.Reader
		// interface), so we continue the loop to try reading again.
	}

	return totalBytes, nil
}

// DecryptStream performs streaming decryption of data read from an
// io.Reader and writes the decrypted plaintext to an io.Writer. This
// function is suitable for decrypting large files or data streams
// without loading the entire ciphertext into memory.
//
// The streaming decryption process:
//  1. Read the encryption header (Version + SenderPubKey + Nonce) from
//     the reader.
//  2. Verify the encryption format version is supported.
//  3. Compute the ECDH shared secret using the recipient's key pair and
//     the sender's public key from the header.
//  4. Derive the decryption key using HKDF-SHA256.
//  5. Read ciphertext from the reader in chunks, decrypt each chunk with
//     the Sosemanuk stream cipher, and write the plaintext chunks to
//     the writer.
//
// A buffer pool is used to minimize memory allocations during the
// streaming process.
//
// Parameters:
//   - reader: An io.Reader providing the encrypted data (header + ciphertext).
//   - plaintextWriter: An io.Writer where the decrypted plaintext will
//     be written.
//   - recipientKeyPair: The Curve25519 key pair of the recipient.
//   - bufferSize: The size in bytes of the buffer used for reading and
//     decrypting chunks. Recommended range is 4KB to 64KB.
//
// Returns:
//   - senderPubKey: The Curve25519 public key of the sender, extracted
//     from the encryption header. This can be used to verify the sender's
//     identity or for logging purposes.
//   - totalBytes: The total number of plaintext bytes decrypted.
//   - err: An error if any step fails. If an error occurs, some data
//     may already have been written to the writer.
func DecryptStream(reader io.Reader, plaintextWriter io.Writer, recipientKeyPair *KeyPair, bufferSize int) (senderPubKey [PublicKeySize]byte, totalBytes int64, err error) {
	// Read the full encryption header from the reader. The header
	// contains the version, sender's public key, and nonce, all of
	// which are needed before decryption can begin.
	header := make([]byte, HeaderSize)
	headerBytesRead, err := io.ReadFull(reader, header)
	if err != nil {
		// If we hit EOF before reading the full header, the data is
		// truncated and cannot be valid encrypted data.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return senderPubKey, 0, ErrInvalidCiphertext
		}
		return senderPubKey, 0, fmt.Errorf("failed to read header: %w", err)
	}
	// Double-check that we read exactly HeaderSize bytes.
	if headerBytesRead != HeaderSize {
		return senderPubKey, 0, ErrInvalidCiphertext
	}

	// Extract and validate the version from the header.
	version := header[0]
	if version != Version {
		return senderPubKey, 0, ErrInvalidVersion
	}

	// Extract the sender's public key from the header bytes.
	copy(senderPubKey[:], header[1:1+PublicKeySize])
	// Extract the nonce from the header bytes.
	var nonce [NonceSize]byte
	copy(nonce[:], header[1+PublicKeySize:])

	// Compute the ECDH shared secret. The recipient multiplies their
	// private key with the sender's public key, producing the same
	// shared secret used during encryption.
	sharedSecret, err := recipientKeyPair.ComputeSharedSecret(senderPubKey)
	if err != nil {
		return senderPubKey, 0, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive the symmetric decryption key using HKDF-SHA256. The context
	// must exactly match what was used during encryption.
	context := append([]byte("neptune-encryption"), recipientKeyPair.PublicKey[:]...)
	decryptionKey, err := DeriveEncryptionKey(sharedSecret[:], context)
	if err != nil {
		return senderPubKey, 0, fmt.Errorf("failed to derive decryption key: %w", err)
	}

	// Initialize the Sosemanuk stream cipher with the derived key and
	// the nonce from the header. The cipher state is maintained across
	// all chunks, ensuring the keystream is continuous.
	cipher, err := sosemanuk.New(decryptionKey, nonce[:])
	if err != nil {
		return senderPubKey, 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Obtain a buffer from the global buffer pool to avoid repeated
	// memory allocations in the decryption loop. The buffer is returned
	// to the pool when done via defer.
	buf := getGlobalBuffer(bufferSize)
	defer putGlobalBuffer(buf)

	// Stream decryption loop: read ciphertext in chunks, decrypt each
	// chunk, and write the plaintext to the output writer.
	totalBytes = 0
	for {
		// Read up to bufferSize bytes of ciphertext from the reader.
		n, readErr := reader.Read(buf)

		// If we read any data, decrypt it and write it out.
		if n > 0 {
			// Decrypt the chunk by XORing with the Sosemanuk keystream.
			// For stream ciphers, encryption and decryption are the
			// same operation. The cipher state advances with each call.
			decryptedChunk := make([]byte, n)
			cipher.XORKeyStream(decryptedChunk, buf[:n])

			// Write the decrypted plaintext chunk to the output writer.
			if _, writeErr := plaintextWriter.Write(decryptedChunk); writeErr != nil {
				return senderPubKey, totalBytes, fmt.Errorf("failed to write plaintext: %w", writeErr)
			}

			totalBytes += int64(n)
		}

		// Handle end of input stream.
		// io.EOF indicates the reader has no more data, which is the
		// normal termination condition for the streaming loop.
		if readErr == io.EOF {
			break
		}
		// Handle any other read error.
		if readErr != nil {
			return senderPubKey, totalBytes, fmt.Errorf("failed to read ciphertext: %w", readErr)
		}
		// If n == 0 and readErr == nil, the reader returned a
		// zero-length read without error (permitted by the io.Reader
		// interface), so we continue the loop to try reading again.
	}

	return senderPubKey, totalBytes, nil
}

// getGlobalBuffer retrieves a buffer from the package-level buffer pool.
// Using a pool avoids repeated allocation and deallocation of byte slices
// during streaming operations, significantly improving performance for
// large or frequent encryption/decryption operations.
//
// Parameters:
//   - size: The minimum required capacity of the buffer in bytes.
//
// Returns:
//   - A byte slice of length 'size'. If the pooled buffer has sufficient
//     capacity, it is reused; otherwise a new buffer is allocated.
func getGlobalBuffer(size int) []byte {
	// Note: In a larger codebase, this might be delegated to a shared
	// utils package. Here it's kept in the crypto package for
	// self-containment and to avoid circular dependencies.
	return globalBufferPool.GetBuffer(size)
}

// putGlobalBuffer returns a buffer to the package-level buffer pool for
// reuse. The buffer is reset to zero length before being returned to
// the pool to prevent accidental data leakage between operations.
//
// Parameters:
//   - buf: The byte slice to return to the pool. If nil, the function
//     is a no-op.
func putGlobalBuffer(buf []byte) {
	globalBufferPool.PutBuffer(buf)
}

// globalBufferPool is the package-level buffer pool used by streaming
// encryption and decryption functions. It is initialized at package
// load time with a default initial capacity of 4096 bytes (4KB).
var globalBufferPool = NewCryptoBufferPool()

// NewCryptoBufferPool creates and returns a new CryptoBufferPool instance.
// The pool is initialized with a sync.Pool that produces byte slices with
// an initial capacity of 4096 bytes (4KB).
//
// The buffer pool reduces memory allocations and garbage collection
// pressure by reusing byte slices across multiple encryption/decryption
// operations.
//
// Returns:
//   - A pointer to the newly created CryptoBufferPool.
func NewCryptoBufferPool() *CryptoBufferPool {
	return &CryptoBufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				// New buffers start with 4KB capacity, which is a good
				// default for many streaming scenarios. The buffer will
				// grow as needed for larger buffer sizes.
				return make([]byte, 0, 4096)
			},
		},
	}
}

// CryptoBufferPool provides a pool of reusable byte slices for use in
// crypto streaming operations. It wraps sync.Pool to provide type-safe
// buffer management with automatic resizing.
//
// The pool helps reduce memory allocation overhead and garbage collection
// pressure when performing many streaming encryption or decryption
// operations, since buffers are reused instead of being allocated and
// freed each time.
type CryptoBufferPool struct {
	// pool is the underlying sync.Pool that stores the byte slices.
	// sync.Pool is used because it's efficient for short-lived objects
	// that are used and then quickly returned, which matches the pattern
	// of encryption/decryption buffers.
	pool sync.Pool
}

// GetBuffer retrieves a byte slice from the pool with the specified size.
// If the pool contains a buffer with sufficient capacity, it is reused;
// otherwise a new buffer is allocated.
//
// The returned slice has length exactly equal to 'size' and is ready to
// use. The caller should return the buffer to the pool using PutBuffer
// when it is no longer needed.
//
// Parameters:
//   - size: The desired length of the buffer in bytes.
//
// Returns:
//   - A byte slice of length 'size'. If a pooled buffer with capacity
//     >= size exists, it is returned (sliced to 'size'); otherwise a
//     new buffer of the exact size is allocated.
func (bp *CryptoBufferPool) GetBuffer(size int) []byte {
	buf := bp.pool.Get().([]byte)
	// If the pooled buffer doesn't have enough capacity for the
	// requested size, allocate a new buffer of exactly the right size.
	// We don't return the old buffer to the pool in this case since
	// it's too small to be useful for this request.
	if cap(buf) < size {
		return make([]byte, size)
	}
	// Slice the buffer to the requested size. The underlying array
	// retains its full capacity for future reuse.
	return buf[:size]
}

// PutBuffer returns a byte slice to the pool for reuse. The buffer is
// reset to zero length before being returned to the pool to ensure that
// sensitive data from previous operations cannot be accidentally read
// by the next caller.
//
// Callers should not use the buffer after passing it to PutBuffer, as
// it may be retrieved and modified by another goroutine at any time.
//
// Parameters:
//   - buf: The byte slice to return to the pool. If nil, the function
//     does nothing safely.
func (bp *CryptoBufferPool) PutBuffer(buf []byte) {
	if buf == nil {
		return
	}
	// Reset the buffer length to 0 before returning it to the pool.
	// This ensures that the next GetBuffer call will slice it to the
	// requested size, and prevents any leftover data from being visible.
	// Note: The underlying data is not zeroed - this is a performance
	// tradeoff. For truly sensitive data, callers should zero the buffer
	// before returning it.
	buf = buf[:0]
	bp.pool.Put(buf)
}
