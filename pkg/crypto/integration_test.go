package crypto

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"neptune/pkg/curve25519"
)

// TestEndToEndCommunication tests a complete communication scenario
func TestEndToEndCommunication(t *testing.T) {
	// Alice generates key pair
	aliceKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Alice failed to generate key pair: %v", err)
	}

	// Bob generates key pair
	bobKeyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Bob failed to generate key pair: %v", err)
	}

	// Test messages of different sizes
	messageSizes := []int{10, 100, 1000, 10000}

	for _, size := range messageSizes {
		t.Run("message_size_"+string(rune(size)), func(t *testing.T) {
			// Alice creates a message
			message := make([]byte, size)
			rand.Read(message)

			// Alice encrypts message for Bob
			encryptedData, err := EncryptWithKeyPair(message, aliceKeyPair, bobKeyPair.PublicKey)
			if err != nil {
				t.Fatalf("Alice failed to encrypt: %v", err)
			}

			// Alice sends encrypted data to Bob (simulate network transmission via serialization)
			serialized := encryptedData.Serialize()

			// Bob receives and deserializes
			receivedData, err := DeserializeEncryptedData(serialized)
			if err != nil {
				t.Fatalf("Bob failed to deserialize: %v", err)
			}

			// Bob decrypts
			decryptedMessage, err := DecryptWithKeyPair(receivedData, bobKeyPair)
			if err != nil {
				t.Fatalf("Bob failed to decrypt: %v", err)
			}

			// Verify message
			if !bytes.Equal(message, decryptedMessage) {
				t.Error("Message integrity check failed")
			}
		})
	}
}

// TestEndToEndFileEncryption tests file encryption/decryption workflow
func TestEndToEndFileEncryption(t *testing.T) {
	// Generate key pairs
	senderKeyPair, _ := GenerateKeyPair()
	recipientKeyPair, _ := GenerateKeyPair()

	// Create a test file
	testFile := "test_encrypted.dat"
	decryptedFile := "test_decrypted.dat"
	defer os.Remove(testFile)
	defer os.Remove(decryptedFile)

	// Write test data
	testData := []byte("This is a test file content for end-to-end encryption testing.\nIt contains multiple lines and special characters: @#$%^&*()")
	err := os.WriteFile(testFile, testData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Read file and encrypt
	fileContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	// Encrypt
	encryptedData, err := EncryptWithKeyPair(fileContent, senderKeyPair, recipientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encrypt file content: %v", err)
	}

	// Serialize and write encrypted data
	serialized := encryptedData.Serialize()
	err = os.WriteFile(testFile, serialized, 0644)
	if err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Read encrypted file and decrypt
	encryptedContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Deserialize and decrypt
	deserializedData, err := DeserializeEncryptedData(encryptedContent)
	if err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	decryptedContent, err := DecryptWithKeyPair(deserializedData, recipientKeyPair)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Write decrypted content
	err = os.WriteFile(decryptedFile, decryptedContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write decrypted file: %v", err)
	}

	// Verify
	if !bytes.Equal(testData, decryptedContent) {
		t.Error("File encryption/decryption roundtrip failed")
	}
}

// TestEndToEndKeyExchange tests the complete key exchange workflow
func TestEndToEndKeyExchange(t *testing.T) {
	// Alice generates key pair and saves to file
	aliceKeyPair, _ := GenerateKeyPair()
	alicePrivKeyFile := "alice_private.key"
	alicePubKeyFile := "alice_public.key"
	defer os.Remove(alicePrivKeyFile)
	defer os.Remove(alicePubKeyFile)

	// Save Alice's key pair
	err := curve25519.SaveKeyPairToFile(aliceKeyPair, alicePrivKeyFile, curve25519.EncodingHex)
	if err != nil {
		t.Fatalf("Failed to save Alice's key pair: %v", err)
	}

	err = curve25519.SavePublicKeyToFile(aliceKeyPair.PublicKey, alicePubKeyFile, curve25519.EncodingHex)
	if err != nil {
		t.Fatalf("Failed to save Alice's public key: %v", err)
	}

	// Bob generates key pair
	bobKeyPair, _ := GenerateKeyPair()

	// Bob loads Alice's public key from file
	_, err = curve25519.LoadPublicKeyFromFile(alicePubKeyFile, curve25519.EncodingHex)
	if err != nil {
		t.Fatalf("Bob failed to load Alice's public key: %v", err)
	}

	// Alice loads her private key from file
	aliceLoadedKeyPair, err := curve25519.LoadKeyPairFromFile(alicePrivKeyFile, curve25519.EncodingHex)
	if err != nil {
		t.Fatalf("Alice failed to load her key pair: %v", err)
	}

	// Alice sends message to Bob
	message := []byte("Secret message from Alice to Bob")
	encrypted, err := EncryptWithKeyPair(message, aliceLoadedKeyPair, bobKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	// Bob decrypts
	decrypted, err := DecryptWithKeyPair(encrypted, bobKeyPair)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Error("Key exchange and encryption failed")
	}
}

// TestEndToEndMultipleParties tests communication between multiple parties
func TestEndToEndMultipleParties(t *testing.T) {
	// Create three parties
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	charlie, _ := GenerateKeyPair()

	// Test messages between all pairs
	testCases := []struct {
		name      string
		sender    *curve25519.KeyPair
		receiver  *curve25519.KeyPair
		message   string
	}{
		{"Alice to Bob", alice, bob, "Hi Bob, this is Alice"},
		{"Bob to Alice", bob, alice, "Hi Alice, this is Bob"},
		{"Alice to Charlie", alice, charlie, "Hi Charlie, this is Alice"},
		{"Charlie to Bob", charlie, bob, "Hi Bob, this is Charlie"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := EncryptWithKeyPair([]byte(tc.message), tc.sender, tc.receiver.PublicKey)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := DecryptWithKeyPair(encrypted, tc.receiver)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != tc.message {
				t.Errorf("Message mismatch: got %q, want %q", decrypted, tc.message)
			}
		})
	}
}

// TestEndToEndTiming tests timing behavior
func TestEndToEndTiming(t *testing.T) {
	// Generate keys
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()

	// Test encryption timing with different sizes
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		t.Run("size_"+string(rune(size)), func(t *testing.T) {
			plaintext := make([]byte, size)
			rand.Read(plaintext)

			// Measure encryption time
			start := time.Now()
			encrypted, err := EncryptWithKeyPair(plaintext, sender, receiver.PublicKey)
			encryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Measure decryption time
			start = time.Now()
			decrypted, err := DecryptWithKeyPair(encrypted, receiver)
			decryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify correctness
			if !bytes.Equal(plaintext, decrypted) {
				t.Error("Data integrity check failed")
			}

			// Log timing (not a strict test, just for information)
			t.Logf("Size %d bytes - Encrypt: %v, Decrypt: %v", size, encryptTime, decryptTime)
		})
	}
}

// TestEndToEndEdgeCases tests edge cases
func TestEndToEndEdgeCases(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()

	// Test empty message
	t.Run("empty_message", func(t *testing.T) {
		encrypted, err := EncryptWithKeyPair([]byte{}, sender, receiver.PublicKey)
		if err != nil {
			t.Fatalf("Failed to encrypt empty message: %v", err)
		}

		decrypted, err := DecryptWithKeyPair(encrypted, receiver)
		if err != nil {
			t.Fatalf("Failed to decrypt empty message: %v", err)
		}

		if len(decrypted) != 0 {
			t.Errorf("Expected empty decrypted message, got %d bytes", len(decrypted))
		}
	})

	// Test very large message (1MB)
	t.Run("large_message", func(t *testing.T) {
		plaintext := make([]byte, 1024*1024)
		rand.Read(plaintext)

		encrypted, err := EncryptWithKeyPair(plaintext, sender, receiver.PublicKey)
		if err != nil {
			t.Fatalf("Failed to encrypt large message: %v", err)
		}

		decrypted, err := DecryptWithKeyPair(encrypted, receiver)
		if err != nil {
			t.Fatalf("Failed to decrypt large message: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("Large message integrity check failed")
		}
	})

	// Test special characters
	t.Run("special_characters", func(t *testing.T) {
		plaintext := []byte("Hello\nWorld\r\n!@#$%^&*()_+-=[]{}|;':\",./<>?~`")
		
		encrypted, err := EncryptWithKeyPair(plaintext, sender, receiver.PublicKey)
		if err != nil {
			t.Fatalf("Failed to encrypt special characters: %v", err)
		}

		decrypted, err := DecryptWithKeyPair(encrypted, receiver)
		if err != nil {
			t.Fatalf("Failed to decrypt special characters: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("Special characters integrity check failed")
		}
	})
}

// TestEndToEndConcurrency tests concurrent encryption/decryption
func TestEndToEndConcurrency(t *testing.T) {
	sender, _ := GenerateKeyPair()
	receiver, _ := GenerateKeyPair()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			message := []byte("Concurrent message " + string(rune(id+'0')))
			
			encrypted, err := EncryptWithKeyPair(message, sender, receiver.PublicKey)
			if err != nil {
				t.Errorf("Goroutine %d encryption failed: %v", id, err)
				done <- false
				return
			}

			decrypted, err := DecryptWithKeyPair(encrypted, receiver)
			if err != nil {
				t.Errorf("Goroutine %d decryption failed: %v", id, err)
				done <- false
				return
			}

			if !bytes.Equal(message, decrypted) {
				t.Errorf("Goroutine %d message mismatch", id)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}