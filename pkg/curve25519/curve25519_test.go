package curve25519

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestGenerateKeyPair tests key pair generation
func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	// Check that keys are not all zeros
	var zeroKey [KeySize]byte
	if kp.PrivateKey == zeroKey {
		t.Error("Private key should not be all zeros")
	}
	if kp.PublicKey == zeroKey {
		t.Error("Public key should not be all zeros")
	}

	// Generate another key pair and verify they are different
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() second call failed: %v", err)
	}

	if kp.PrivateKey == kp2.PrivateKey {
		t.Error("Two generated private keys should be different")
	}
	if kp.PublicKey == kp2.PublicKey {
		t.Error("Two generated public keys should be different")
	}
}

// TestGenerateKeyPairDeterministic tests key generation with deterministic reader
func TestGenerateKeyPairDeterministic(t *testing.T) {
	// Create a deterministic reader for testing
	seed := make([]byte, KeySize)
	for i := range seed {
		seed[i] = byte(i)
	}
	reader := bytes.NewReader(seed)

	kp1, err := GenerateKeyPairFromReader(reader)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromReader() failed: %v", err)
	}

	// Reset reader and generate again - should get the same key
	reader = bytes.NewReader(seed)
	kp2, err := GenerateKeyPairFromReader(reader)
	if err != nil {
		t.Fatalf("GenerateKeyPairFromReader() second call failed: %v", err)
	}

	if kp1.PrivateKey != kp2.PrivateKey {
		t.Error("Same seed should produce same private key")
	}
	if kp1.PublicKey != kp2.PublicKey {
		t.Error("Same seed should produce same public key")
	}
}

// TestGenerateKeyPairFromReaderError tests error handling for insufficient randomness
func TestGenerateKeyPairFromReaderError(t *testing.T) {
	// Create a reader with insufficient data
	shortReader := bytes.NewReader([]byte{1, 2, 3})

	_, err := GenerateKeyPairFromReader(shortReader)
	if err == nil {
		t.Error("Expected error for insufficient randomness")
	}
}

// TestComputeSharedSecret tests ECDH shared secret computation
func TestComputeSharedSecret(t *testing.T) {
	// Alice generates her key pair
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's key pair: %v", err)
	}

	// Bob generates his key pair
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's key pair: %v", err)
	}

	// Alice computes shared secret using Bob's public key
	aliceShared, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("Alice failed to compute shared secret: %v", err)
	}

	// Bob computes shared secret using Alice's public key
	bobShared, err := ComputeSharedSecret(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("Bob failed to compute shared secret: %v", err)
	}

	// Both shared secrets should be identical
	if aliceShared != bobShared {
		t.Error("Shared secrets should be identical")
	}

	// Shared secret should not be all zeros
	var zero [KeySize]byte
	if aliceShared == zero {
		t.Error("Shared secret should not be all zeros")
	}
}

// TestComputeSharedSecretFromKeyPair tests the KeyPair method
func TestComputeSharedSecretFromKeyPair(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	aliceShared, err := alice.ComputeSharedSecret(bob.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecretFromKeyPair failed: %v", err)
	}

	bobShared, err := bob.ComputeSharedSecret(alice.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecretFromKeyPair failed: %v", err)
	}

	if aliceShared != bobShared {
		t.Error("Shared secrets should be identical")
	}
}

// TestSerializeDeserializeHex tests hex serialization/deserialization
func TestSerializeDeserializeHex(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	// Serialize
	privateKeyStr := SerializePrivateKey(kp.PrivateKey, EncodingHex)
	publicKeyStr := SerializePublicKey(kp.PublicKey, EncodingHex)

	// Verify length (32 bytes = 64 hex characters)
	if len(privateKeyStr) != 64 {
		t.Errorf("Expected private key hex length 64, got %d", len(privateKeyStr))
	}
	if len(publicKeyStr) != 64 {
		t.Errorf("Expected public key hex length 64, got %d", len(publicKeyStr))
	}

	// Deserialize
	privateKey, err := DeserializePrivateKey(privateKeyStr, EncodingHex)
	if err != nil {
		t.Fatalf("DeserializePrivateKey failed: %v", err)
	}
	publicKey, err := DeserializePublicKey(publicKeyStr, EncodingHex)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}

	// Verify round-trip
	if privateKey != kp.PrivateKey {
		t.Error("Private key round-trip failed")
	}
	if publicKey != kp.PublicKey {
		t.Error("Public key round-trip failed")
	}
}

// TestSerializeDeserializeBase64 tests base64 serialization/deserialization
func TestSerializeDeserializeBase64(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	// Serialize
	privateKeyStr := SerializePrivateKey(kp.PrivateKey, EncodingBase64)
	publicKeyStr := SerializePublicKey(kp.PublicKey, EncodingBase64)

	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		t.Errorf("Private key is not valid base64: %v", err)
	}
	_, err = base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil {
		t.Errorf("Public key is not valid base64: %v", err)
	}

	// Deserialize
	privateKey, err := DeserializePrivateKey(privateKeyStr, EncodingBase64)
	if err != nil {
		t.Fatalf("DeserializePrivateKey failed: %v", err)
	}
	publicKey, err := DeserializePublicKey(publicKeyStr, EncodingBase64)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}

	// Verify round-trip
	if privateKey != kp.PrivateKey {
		t.Error("Private key round-trip failed")
	}
	if publicKey != kp.PublicKey {
		t.Error("Public key round-trip failed")
	}
}

// TestSerializeDeserializeBase64URL tests base64url serialization/deserialization
func TestSerializeDeserializeBase64URL(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	// Serialize
	privateKeyStr := SerializePrivateKey(kp.PrivateKey, EncodingBase64URL)
	publicKeyStr := SerializePublicKey(kp.PublicKey, EncodingBase64URL)

	// Verify it's valid base64url
	_, err = base64.URLEncoding.DecodeString(privateKeyStr)
	if err != nil {
		t.Errorf("Private key is not valid base64url: %v", err)
	}
	_, err = base64.URLEncoding.DecodeString(publicKeyStr)
	if err != nil {
		t.Errorf("Public key is not valid base64url: %v", err)
	}

	// Deserialize
	privateKey, err := DeserializePrivateKey(privateKeyStr, EncodingBase64URL)
	if err != nil {
		t.Fatalf("DeserializePrivateKey failed: %v", err)
	}
	publicKey, err := DeserializePublicKey(publicKeyStr, EncodingBase64URL)
	if err != nil {
		t.Fatalf("DeserializePublicKey failed: %v", err)
	}

	// Verify round-trip
	if privateKey != kp.PrivateKey {
		t.Error("Private key round-trip failed")
	}
	if publicKey != kp.PublicKey {
		t.Error("Public key round-trip failed")
	}
}

// TestSerializeKeyPair tests key pair serialization
func TestSerializeKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	privateKeyStr, publicKeyStr := SerializeKeyPair(kp, EncodingHex)

	// Verify both strings are valid hex
	_, err = hex.DecodeString(privateKeyStr)
	if err != nil {
		t.Errorf("Private key string is not valid hex: %v", err)
	}
	_, err = hex.DecodeString(publicKeyStr)
	if err != nil {
		t.Errorf("Public key string is not valid hex: %v", err)
	}
}

// TestDeserializeKeyPair tests key pair deserialization
func TestDeserializeKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	privateKeyStr, publicKeyStr := SerializeKeyPair(kp, EncodingHex)

	kp2, err := DeserializeKeyPair(privateKeyStr, publicKeyStr, EncodingHex)
	if err != nil {
		t.Fatalf("DeserializeKeyPair failed: %v", err)
	}

	if kp.PrivateKey != kp2.PrivateKey {
		t.Error("Private keys don't match")
	}
	if kp.PublicKey != kp2.PublicKey {
		t.Error("Public keys don't match")
	}
}

// TestDeserializeInvalidKey tests deserialization error handling
func TestDeserializeInvalidKey(t *testing.T) {
	// Test invalid hex
	_, err := DeserializePrivateKey("invalid-hex!", EncodingHex)
	if err == nil {
		t.Error("Expected error for invalid hex string")
	}

	// Test wrong size
	shortHex := hex.EncodeToString([]byte{1, 2, 3})
	_, err = DeserializePrivateKey(shortHex, EncodingHex)
	if err == nil {
		t.Error("Expected error for wrong key size")
	}
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got %v", err)
	}

	// Test invalid base64
	_, err = DeserializePrivateKey("invalid-base64!!!", EncodingBase64)
	if err == nil {
		t.Error("Expected error for invalid base64 string")
	}
}

// TestSaveLoadKeyPairFile tests saving and loading key pairs to/from files
func TestSaveLoadKeyPairFile(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	filename := "test_keypair.txt"
	defer os.Remove(filename)

	// Save key pair
	err = SaveKeyPairToFile(kp, filename, EncodingHex)
	if err != nil {
		t.Fatalf("SaveKeyPairToFile failed: %v", err)
	}

	// Load key pair
	kp2, err := LoadKeyPairFromFile(filename, EncodingHex)
	if err != nil {
		t.Fatalf("LoadKeyPairFromFile failed: %v", err)
	}

	// Verify keys match
	if kp.PrivateKey != kp2.PrivateKey {
		t.Error("Private keys don't match after file round-trip")
	}
	if kp.PublicKey != kp2.PublicKey {
		t.Error("Public keys don't match after file round-trip")
	}
}

// TestSaveLoadPublicKeyFile tests saving and loading public keys to/from files
func TestSaveLoadPublicKeyFile(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	filename := "test_publickey.txt"
	defer os.Remove(filename)

	// Save public key
	err = SavePublicKeyToFile(kp.PublicKey, filename, EncodingBase64)
	if err != nil {
		t.Fatalf("SavePublicKeyToFile failed: %v", err)
	}

	// Load public key
	publicKey, err := LoadPublicKeyFromFile(filename, EncodingBase64)
	if err != nil {
		t.Fatalf("LoadPublicKeyFromFile failed: %v", err)
	}

	// Verify key matches
	if kp.PublicKey != publicKey {
		t.Error("Public keys don't match after file round-trip")
	}
}

// TestLoadKeyPairFileNotFound tests error handling for missing file
func TestLoadKeyPairFileNotFound(t *testing.T) {
	_, err := LoadKeyPairFromFile("nonexistent_file.txt", EncodingHex)
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// TestLoadPublicKeyFileNotFound tests error handling for missing file
func TestLoadPublicKeyFileNotFound(t *testing.T) {
	_, err := LoadPublicKeyFromFile("nonexistent_file.txt", EncodingHex)
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// TestKeyPairString tests the String method (security check)
func TestKeyPairString(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	// Test String() method
	str := kp.String()
	
	// Verify private key is not exposed
	privateKeyHex := hex.EncodeToString(kp.PrivateKey[:])
	if strings.Contains(str, privateKeyHex) {
		t.Error("String() should not expose private key in hex")
	}
	if strings.Contains(str, "PrivateKey: [") && !strings.Contains(str, "[REDACTED]") {
		t.Error("String() should redact private key")
	}

	// Verify public key is shown
	publicKeyHex := hex.EncodeToString(kp.PublicKey[:])
	if !strings.Contains(str, publicKeyHex) {
		t.Error("String() should show public key")
	}
}

// TestKeyPairSafeString tests the SafeString method
func TestKeyPairSafeString(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	str := kp.SafeString()

	// Verify both keys are redacted
	privateKeyHex := hex.EncodeToString(kp.PrivateKey[:])
	publicKeyHex := hex.EncodeToString(kp.PublicKey[:])

	if strings.Contains(str, privateKeyHex) {
		t.Error("SafeString() should not expose private key")
	}
	if strings.Contains(str, publicKeyHex) {
		t.Error("SafeString() should not expose public key")
	}
	if !strings.Contains(str, "[REDACTED]") {
		t.Error("SafeString() should contain [REDACTED]")
	}
}

// TestMultipleEncodings tests different encoding formats
func TestMultipleEncodings(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	encodings := []EncodingType{EncodingHex, EncodingBase64, EncodingBase64URL}

	for _, encoding := range encodings {
		privateKeyStr, publicKeyStr := SerializeKeyPair(kp, encoding)
		
		kp2, err := DeserializeKeyPair(privateKeyStr, publicKeyStr, encoding)
		if err != nil {
			t.Errorf("Failed to deserialize with encoding %v: %v", encoding, err)
			continue
		}

		if kp.PrivateKey != kp2.PrivateKey {
			t.Errorf("Private key mismatch with encoding %v", encoding)
		}
		if kp.PublicKey != kp2.PublicKey {
			t.Errorf("Public key mismatch with encoding %v", encoding)
		}
	}
}

// TestECDHWithMultipleParties tests ECDH with multiple parties
func TestECDHWithMultipleParties(t *testing.T) {
	// Generate key pairs for Alice, Bob, and Charlie
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	charlie, _ := GenerateKeyPair()

	// Alice-Bob shared secret
	aliceBobSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	bobAliceSecret, _ := ComputeSharedSecret(bob.PrivateKey, alice.PublicKey)
	if aliceBobSecret != bobAliceSecret {
		t.Error("Alice-Bob shared secrets don't match")
	}

	// Alice-Charlie shared secret
	aliceCharlieSecret, _ := ComputeSharedSecret(alice.PrivateKey, charlie.PublicKey)
	charlieAliceSecret, _ := ComputeSharedSecret(charlie.PrivateKey, alice.PublicKey)
	if aliceCharlieSecret != charlieAliceSecret {
		t.Error("Alice-Charlie shared secrets don't match")
	}

	// Bob-Charlie shared secret
	bobCharlieSecret, _ := ComputeSharedSecret(bob.PrivateKey, charlie.PublicKey)
	charlieBobSecret, _ := ComputeSharedSecret(charlie.PrivateKey, bob.PublicKey)
	if bobCharlieSecret != charlieBobSecret {
		t.Error("Bob-Charlie shared secrets don't match")
	}

	// Verify that different pairs produce different shared secrets
	if aliceBobSecret == aliceCharlieSecret {
		t.Error("Different pairs should produce different shared secrets")
	}
	if aliceBobSecret == bobCharlieSecret {
		t.Error("Different pairs should produce different shared secrets")
	}
}

// TestConcurrentKeyGeneration tests concurrent key generation
func TestConcurrentKeyGeneration(t *testing.T) {
	const numGoroutines = 100
	done := make(chan *KeyPair, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			kp, err := GenerateKeyPair()
			if err != nil {
				t.Errorf("Concurrent GenerateKeyPair failed: %v", err)
				done <- nil
				return
			}
			done <- kp
		}()
	}

	keys := make(map[[KeySize]byte]bool)
	for i := 0; i < numGoroutines; i++ {
		kp := <-done
		if kp == nil {
			continue
		}
		if keys[kp.PrivateKey] {
			t.Error("Duplicate private key generated")
		}
		keys[kp.PrivateKey] = true
	}
}

// TestKeySizeConstant verifies the key size constant
func TestKeySizeConstant(t *testing.T) {
	if KeySize != 32 {
		t.Errorf("Expected KeySize to be 32, got %d", KeySize)
	}
}

// BenchmarkGenerateKeyPair benchmarks key pair generation
func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKeyPair()
		if err != nil {
			b.Fatalf("GenerateKeyPair failed: %v", err)
		}
	}
}

// BenchmarkComputeSharedSecret benchmarks shared secret computation
func BenchmarkComputeSharedSecret(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
		if err != nil {
			b.Fatalf("ComputeSharedSecret failed: %v", err)
		}
	}
}

// BenchmarkSerializeHex benchmarks hex serialization
func BenchmarkSerializeHex(b *testing.B) {
	kp, _ := GenerateKeyPair()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SerializePrivateKey(kp.PrivateKey, EncodingHex)
	}
}

// BenchmarkDeserializeHex benchmarks hex deserialization
func BenchmarkDeserializeHex(b *testing.B) {
	kp, _ := GenerateKeyPair()
	str := SerializePrivateKey(kp.PrivateKey, EncodingHex)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializePrivateKey(str, EncodingHex)
	}
}

// FuzzDeserializePrivateKey tests deserialization with fuzzing
func FuzzDeserializePrivateKey(f *testing.F) {
	// Add seed corpus
	kp, _ := GenerateKeyPair()
	f.Add(SerializePrivateKey(kp.PrivateKey, EncodingHex))
	f.Add(SerializePrivateKey(kp.PrivateKey, EncodingBase64))
	f.Add(SerializePrivateKey(kp.PrivateKey, EncodingBase64URL))

	f.Fuzz(func(t *testing.T, data string) {
		// Try all encodings
		for _, encoding := range []EncodingType{EncodingHex, EncodingBase64, EncodingBase64URL} {
			key, err := DeserializePrivateKey(data, encoding)
			if err == nil {
				// If deserialization succeeded, verify the key
				if len(key) != KeySize {
					t.Errorf("Deserialized key has wrong size: %d", len(key))
				}
			}
		}
	})
}

// TestIntegration tests a complete workflow
func TestIntegration(t *testing.T) {
	// Generate Alice's key pair
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's key pair: %v", err)
	}

	// Save Alice's key pair to file
	aliceKeyFile := "alice_keypair.txt"
	defer os.Remove(aliceKeyFile)
	err = SaveKeyPairToFile(alice, aliceKeyFile, EncodingBase64)
	if err != nil {
		t.Fatalf("Failed to save Alice's key pair: %v", err)
	}

	// Load Alice's key pair from file
	aliceLoaded, err := LoadKeyPairFromFile(aliceKeyFile, EncodingBase64)
	if err != nil {
		t.Fatalf("Failed to load Alice's key pair: %v", err)
	}

	// Generate Bob's key pair
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's key pair: %v", err)
	}

	// Save Bob's public key to file
	bobPubKeyFile := "bob_publickey.txt"
	defer os.Remove(bobPubKeyFile)
	err = SavePublicKeyToFile(bob.PublicKey, bobPubKeyFile, EncodingBase64)
	if err != nil {
		t.Fatalf("Failed to save Bob's public key: %v", err)
	}

	// Load Bob's public key from file
	bobPubKey, err := LoadPublicKeyFromFile(bobPubKeyFile, EncodingBase64)
	if err != nil {
		t.Fatalf("Failed to load Bob's public key: %v", err)
	}

	// Alice computes shared secret using Bob's public key
	aliceShared, err := aliceLoaded.ComputeSharedSecret(bobPubKey)
	if err != nil {
		t.Fatalf("Alice failed to compute shared secret: %v", err)
	}

	// Bob computes shared secret using Alice's public key
	bobShared, err := bob.ComputeSharedSecret(aliceLoaded.PublicKey)
	if err != nil {
		t.Fatalf("Bob failed to compute shared secret: %v", err)
	}

	// Verify shared secrets match
	if aliceShared != bobShared {
		t.Error("Shared secrets don't match")
	}

	// Verify loaded keys match original
	if alice.PrivateKey != aliceLoaded.PrivateKey {
		t.Error("Alice's private key doesn't match after loading")
	}
	if alice.PublicKey != aliceLoaded.PublicKey {
		t.Error("Alice's public key doesn't match after loading")
	}
	if bob.PublicKey != bobPubKey {
		t.Error("Bob's public key doesn't match after loading")
	}
}

// TestRandomnessQuality tests the quality of random key generation
func TestRandomnessQuality(t *testing.T) {
	const numSamples = 1000
	keys := make(map[[KeySize]byte]bool, numSamples)

	for i := 0; i < numSamples; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair failed: %v", err)
		}

		if keys[kp.PrivateKey] {
			t.Error("Duplicate private key generated - randomness quality issue")
		}
		keys[kp.PrivateKey] = true
	}

	// Check that we got all unique keys
	if len(keys) != numSamples {
		t.Errorf("Expected %d unique keys, got %d", numSamples, len(keys))
	}
}

// TestInvalidEncodingType tests behavior with invalid encoding type
func TestInvalidEncodingType(t *testing.T) {
	kp, _ := GenerateKeyPair()
	
	// Test with invalid encoding type (should default to hex)
	invalidEncoding := EncodingType(999)
	
	// Serialization should not panic
	privateKeyStr := SerializePrivateKey(kp.PrivateKey, invalidEncoding)
	publicKeyStr := SerializePublicKey(kp.PublicKey, invalidEncoding)
	
	// Should default to hex encoding
	expectedPrivate := hex.EncodeToString(kp.PrivateKey[:])
	expectedPublic := hex.EncodeToString(kp.PublicKey[:])
	
	if privateKeyStr != expectedPrivate {
		t.Error("Invalid encoding should default to hex for private key")
	}
	if publicKeyStr != expectedPublic {
		t.Error("Invalid encoding should default to hex for public key")
	}
}