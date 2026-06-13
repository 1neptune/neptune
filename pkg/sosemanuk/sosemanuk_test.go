package sosemanuk

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestNew tests the creation of a new Sosemanuk cipher
func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		iv      []byte
		wantErr error
	}{
		{
			name:    "valid 128-bit key",
			key:     make([]byte, KeySize128),
			iv:      make([]byte, IVSize),
			wantErr: nil,
		},
		{
			name:    "valid 256-bit key",
			key:     make([]byte, KeySize256),
			iv:      make([]byte, IVSize),
			wantErr: nil,
		},
		{
			name:    "invalid key size (too short)",
			key:     make([]byte, 8),
			iv:      make([]byte, IVSize),
			wantErr: ErrInvalidKeySize,
		},
		{
			name:    "invalid key size (too long)",
			key:     make([]byte, 64),
			iv:      make([]byte, IVSize),
			wantErr: ErrInvalidKeySize,
		},
		{
			name:    "invalid IV size (too short)",
			key:     make([]byte, KeySize128),
			iv:      make([]byte, 8),
			wantErr: ErrInvalidIVSize,
		},
		{
			name:    "invalid IV size (too long)",
			key:     make([]byte, KeySize128),
			iv:      make([]byte, 32),
			wantErr: ErrInvalidIVSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.key, tt.iv)
			if err != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestKeySchedule tests the key schedule function
func TestKeySchedule(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr error
	}{
		{
			name:    "128-bit key",
			key:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			wantErr: nil,
		},
		{
			name:    "256-bit key",
			key:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
			wantErr: nil,
		},
		{
			name:    "invalid key size",
			key:     []byte{0x01, 0x02, 0x03, 0x04},
			wantErr: ErrInvalidKeySize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Sosemanuk{}
			err := s.keySchedule(tt.key)
			if err != tt.wantErr {
				t.Errorf("keySchedule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestIVSetup tests the IV setup function
func TestIVSetup(t *testing.T) {
	tests := []struct {
		name    string
		iv      []byte
		wantErr error
	}{
		{
			name:    "valid IV",
			iv:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			wantErr: nil,
		},
		{
			name:    "invalid IV size",
			iv:      []byte{0x01, 0x02, 0x03, 0x04},
			wantErr: ErrInvalidIVSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Sosemanuk{}
			// Initialize with a valid key first
			_ = s.keySchedule(make([]byte, KeySize128))
			err := s.ivSetup(tt.iv)
			if err != tt.wantErr {
				t.Errorf("ivSetup() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestEncryptDecrypt tests encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	// Fill with random data
	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message for Sosemanuk cipher.")
	ciphertext := cipher.Encrypt(plaintext)

	// Create a new cipher instance for decryption
	cipher2, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher for decryption: %v", err)
	}

	decrypted := cipher2.Decrypt(ciphertext)

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption failed: got %v, want %v", decrypted, plaintext)
	}
}

// TestEncryptDecrypt256BitKey tests encryption and decryption with 256-bit key
func TestEncryptDecrypt256BitKey(t *testing.T) {
	key := make([]byte, KeySize256)
	iv := make([]byte, IVSize)

	// Fill with random data
	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message for Sosemanuk cipher with 256-bit key.")
	ciphertext := cipher.Encrypt(plaintext)

	// Create a new cipher instance for decryption
	cipher2, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher for decryption: %v", err)
	}

	decrypted := cipher2.Decrypt(ciphertext)

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption failed: got %v, want %v", decrypted, plaintext)
	}
}

// TestXORKeyStream tests the XORKeyStream function
func TestXORKeyStream(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("Test XOR keystream functionality")
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)

	// Verify that ciphertext is different from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("XORKeyStream did not modify the plaintext")
	}

	// Decrypt using the same cipher (reset first)
	cipher2, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher for decryption: %v", err)
	}

	decrypted := make([]byte, len(ciphertext))
	cipher2.XORKeyStream(decrypted, ciphertext)

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("XORKeyStream decryption failed: got %v, want %v", decrypted, plaintext)
	}
}

// TestNextWord tests the NextWord function
func TestNextWord(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Generate multiple words and verify they are not all zeros
	var hasNonZero bool
	for i := 0; i < 100; i++ {
		word := cipher.NextWord()
		if word != 0 {
			hasNonZero = true
			break
		}
	}

	if !hasNonZero {
		t.Error("NextWord returned all zeros")
	}
}

// TestNextBytes tests the NextBytes function
func TestNextBytes(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Test various lengths
	lengths := []int{1, 4, 7, 16, 32, 100, 1000}

	for _, length := range lengths {
		t.Run("length_"+string(rune(length)), func(t *testing.T) {
			buf := make([]byte, length)
			cipher.NextBytes(buf)

			// Check that not all bytes are zero
			var hasNonZero bool
			for _, b := range buf {
				if b != 0 {
					hasNonZero = true
					break
				}
			}

			if !hasNonZero {
				t.Errorf("NextBytes returned all zeros for length %d", length)
			}
		})

		// Reset cipher for next test
		cipher, _ = New(key, iv)
	}
}

// TestKeyStream tests the KeyStream function
func TestKeyStream(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	keystream := cipher.KeyStream(100)

	if len(keystream) != 100 {
		t.Errorf("KeyStream returned wrong length: got %d, want 100", len(keystream))
	}

	// Check that not all bytes are zero
	var hasNonZero bool
	for _, b := range keystream {
		if b != 0 {
			hasNonZero = true
			break
		}
	}

	if !hasNonZero {
		t.Error("KeyStream returned all zeros")
	}
}

// TestDeterministic tests that the cipher is deterministic
func TestDeterministic(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	// Use fixed values for determinism
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}

	cipher1, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher1: %v", err)
	}

	cipher2, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher2: %v", err)
	}

	// Generate keystreams from both ciphers
	ks1 := cipher1.KeyStream(100)
	ks2 := cipher2.KeyStream(100)

	if !bytes.Equal(ks1, ks2) {
		t.Error("Cipher is not deterministic - same key/IV produced different keystreams")
	}
}

// TestDifferentKeys tests that different keys produce different keystreams
func TestDifferentKeys(t *testing.T) {
	key1 := make([]byte, KeySize128)
	key2 := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key1)
	rand.Read(key2)
	rand.Read(iv)

	cipher1, err := New(key1, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher1: %v", err)
	}

	cipher2, err := New(key2, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher2: %v", err)
	}

	ks1 := cipher1.KeyStream(100)
	ks2 := cipher2.KeyStream(100)

	if bytes.Equal(ks1, ks2) {
		t.Error("Different keys produced the same keystream")
	}
}

// TestDifferentIVs tests that different IVs produce different keystreams
func TestDifferentIVs(t *testing.T) {
	key := make([]byte, KeySize128)
	iv1 := make([]byte, IVSize)
	iv2 := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv1)
	rand.Read(iv2)

	cipher1, err := New(key, iv1)
	if err != nil {
		t.Fatalf("Failed to create cipher1: %v", err)
	}

	cipher2, err := New(key, iv2)
	if err != nil {
		t.Fatalf("Failed to create cipher2: %v", err)
	}

	ks1 := cipher1.KeyStream(100)
	ks2 := cipher2.KeyStream(100)

	if bytes.Equal(ks1, ks2) {
		t.Error("Different IVs produced the same keystream")
	}
}

// TestEmptyPlaintext tests encryption of empty plaintext
func TestEmptyPlaintext(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte{}
	ciphertext := cipher.Encrypt(plaintext)

	if len(ciphertext) != 0 {
		t.Errorf("Empty plaintext produced non-empty ciphertext: %d bytes", len(ciphertext))
	}
}

// TestLargeData tests encryption of large data
func TestLargeData(t *testing.T) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Test with 1MB of data
	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	ciphertext := cipher.Encrypt(plaintext)

	// Create a new cipher instance for decryption
	cipher2, err := New(key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher for decryption: %v", err)
	}

	decrypted := cipher2.Decrypt(ciphertext)

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Large data encryption/decryption failed")
	}
}

// TestReset tests the Reset function
func TestReset(t *testing.T) {
	key := make([]byte, KeySize128)
	iv1 := make([]byte, IVSize)
	iv2 := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv1)
	rand.Read(iv2)

	cipher, err := New(key, iv1)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	ks1 := cipher.KeyStream(100)

	// Reset with different IV
	err = cipher.Reset(key, iv2)
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	ks2 := cipher.KeyStream(100)

	if bytes.Equal(ks1, ks2) {
		t.Error("Reset with different IV produced same keystream")
	}
}

// TestMulAlpha tests the mulAlpha function
func TestMulAlpha(t *testing.T) {
	tests := []struct {
		input  uint32
		output uint32
	}{
		{0x00000000, 0x00000000},
		{0x00000001, 0x00000002},
		{0x80000000, 0x0000001b},
		{0xffffffff, 0xffffffe5}, // (0xffffffff << 1) ^ 0x1b = 0xffffffe5
	}

	for _, tt := range tests {
		result := mulAlpha(tt.input)
		if result != tt.output {
			t.Errorf("mulAlpha(%x) = %x, want %x", tt.input, result, tt.output)
		}
	}
}

// TestMulAlphaX tests the mulAlphaX function
func TestMulAlphaX(t *testing.T) {
	tests := []struct {
		input  uint32
		output uint32
	}{
		{0x00000000, 0x00000000},
		{0x00000002, 0x00000001},
		{0x00000001, 0x800000d9},
	}

	for _, tt := range tests {
		result := mulAlphaX(tt.input)
		if result != tt.output {
			t.Errorf("mulAlphaX(%x) = %x, want %x", tt.input, result, tt.output)
		}
	}
}

// TestSboxApply tests the sboxApply function
func TestSboxApply(t *testing.T) {
	// Test that sboxApply is deterministic
	input := uint32(0x12345678)
	result1 := sboxApply(input)
	result2 := sboxApply(input)

	if result1 != result2 {
		t.Error("sboxApply is not deterministic")
	}

	// Test that different inputs produce different outputs (usually)
	input2 := uint32(0x87654321)
	result3 := sboxApply(input2)

	if input != input2 && result1 == result3 {
		// This is unlikely but possible, so we just log it
		t.Log("Warning: Different inputs produced same sbox output")
	}
}

// TestSboxApplyInv tests the sboxApplyInv function
func TestSboxApplyInv(t *testing.T) {
	// Test that sboxApplyInv is the inverse of sboxApply
	testValues := []uint32{0x00000000, 0x12345678, 0xffffffff, 0x87654321}

	for _, v := range testValues {
		encrypted := sboxApply(v)
		decrypted := sboxApplyInv(encrypted)

		if decrypted != v {
			t.Errorf("sboxApplyInv(sboxApply(%x)) = %x, want %x", v, decrypted, v)
		}
	}
}

// TestLFSRUpdate tests the LFSR update function
func TestLFSRUpdate(t *testing.T) {
	s := &Sosemanuk{}

	// Initialize LFSR with test values
	for i := 0; i < LFSRLength; i++ {
		s.s[i] = uint32(i + 1)
	}

	// Store original state
	originalS0 := s.s[0]
	originalS3 := s.s[3]
	originalS9 := s.s[9]

	s.lfsrUpdate()

	// Check that the LFSR has shifted
	if s.s[0] != originalS0+1 {
		t.Errorf("LFSR did not shift correctly: s[0] = %d, want %d", s.s[0], originalS0+1)
	}

	// Check that the new value was computed correctly
	expectedNewS := mulAlpha(originalS9) ^ originalS3 ^ mulAlphaX(originalS0)
	if s.s[9] != expectedNewS {
		t.Errorf("LFSR new value incorrect: s[9] = %x, want %x", s.s[9], expectedNewS)
	}
}

// TestFSMUpdate tests the FSM update function
func TestFSMUpdate(t *testing.T) {
	s := &Sosemanuk{}

	// Initialize with test values
	for i := 0; i < LFSRLength; i++ {
		s.s[i] = uint32(i + 1)
	}
	s.r1 = 100
	s.r2 = 200

	output := s.fsmUpdate()

	// Check that output is computed correctly
	expectedOutput := s.s[9] + 100 // s[9] + old r1
	if output != expectedOutput {
		t.Errorf("FSM output incorrect: %x, want %x", output, expectedOutput)
	}

	// Check that R1 and R2 were updated
	if s.r1 != s.s[1]+200 { // s[1] + old r2
		t.Errorf("R1 not updated correctly: %x", s.r1)
	}

	if s.r2 != s.s[8]*100 { // s[8] * old r1
		t.Errorf("R2 not updated correctly: %x", s.r2)
	}
}

// TestGenerateOutput tests the generateOutput function
func TestGenerateOutput(t *testing.T) {
	s := &Sosemanuk{}

	// Initialize with test values
	for i := 0; i < LFSRLength; i++ {
		s.s[i] = uint32(i + 1)
	}
	s.r1 = 100
	s.r2 = 200
	s.pos = 4 // Force regeneration

	s.generateOutput()

	// Check that output buffer was filled
	if s.pos != 0 {
		t.Errorf("generateOutput did not reset pos: %d", s.pos)
	}

	// Check that output is not all zeros
	var hasNonZero bool
	for _, v := range s.out {
		if v != 0 {
			hasNonZero = true
			break
		}
	}

	if !hasNonZero {
		t.Error("generateOutput produced all zeros")
	}
}

// BenchmarkEncrypt benchmarks the encryption function
func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, _ := New(key, iv)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(plaintext)
	}
}

// BenchmarkNextWord benchmarks the NextWord function
func BenchmarkNextWord(b *testing.B) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, _ := New(key, iv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.NextWord()
	}
}

// BenchmarkKeyStream benchmarks the KeyStream function
func BenchmarkKeyStream(b *testing.B) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, _ := New(key, iv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.KeyStream(1024)
	}
}

// BenchmarkXORKeyStream benchmarks the XORKeyStream function
// 优化后的版本：批量处理 16 字节，减少函数调用开销
func BenchmarkXORKeyStream(b *testing.B) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, _ := New(key, iv)
	src := make([]byte, 1024)
	dst := make([]byte, 1024)
	rand.Read(src)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Reset(key, iv)
		cipher.XORKeyStream(dst, src)
	}
}

// BenchmarkXORKeyStreamSmall 测试小数据量的 XORKeyStream 性能
func BenchmarkXORKeyStreamSmall(b *testing.B) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, _ := New(key, iv)
	src := make([]byte, 64) // 64 字节
	dst := make([]byte, 64)
	rand.Read(src)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Reset(key, iv)
		cipher.XORKeyStream(dst, src)
	}
}

// BenchmarkXORKeyStreamMedium 测试中等数据量的 XORKeyStream 性能
func BenchmarkXORKeyStreamMedium(b *testing.B) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, _ := New(key, iv)
	src := make([]byte, 16*1024) // 16KB
	dst := make([]byte, 16*1024)
	rand.Read(src)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Reset(key, iv)
		cipher.XORKeyStream(dst, src)
	}
}

// BenchmarkXORKeyStreamLarge 测试大数据量的 XORKeyStream 性能
func BenchmarkXORKeyStreamLarge(b *testing.B) {
	key := make([]byte, KeySize128)
	iv := make([]byte, IVSize)

	rand.Read(key)
	rand.Read(iv)

	cipher, _ := New(key, iv)
	src := make([]byte, 1024*1024) // 1MB
	dst := make([]byte, 1024*1024)
	rand.Read(src)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Reset(key, iv)
		cipher.XORKeyStream(dst, src)
	}
}

// FuzzEncryptDecrypt is a fuzz test for encryption/decryption
func FuzzEncryptDecrypt(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("test key 128bit"), []byte("test iv 16bytes"), []byte("hello world"))
	f.Add(make([]byte, 16), make([]byte, 16), make([]byte, 0))
	f.Add(make([]byte, 32), make([]byte, 16), make([]byte, 1000))

	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		// Only test valid key/IV sizes
		if len(key) != KeySize128 && len(key) != KeySize256 {
			return
		}
		if len(iv) != IVSize {
			return
		}

		cipher, err := New(key, iv)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		ciphertext := cipher.Encrypt(plaintext)

		// Create a new cipher for decryption
		cipher2, err := New(key, iv)
		if err != nil {
			t.Fatalf("Failed to create cipher for decryption: %v", err)
		}

		decrypted := cipher2.Decrypt(ciphertext)

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Decryption failed for plaintext len=%d", len(plaintext))
		}
	})
}