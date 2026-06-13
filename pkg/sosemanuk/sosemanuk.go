// Package sosemanuk implements the Sosemanuk stream cipher.
// Sosemanuk is a software-oriented stream cipher based on SNOW 2.0 and Serpent.
// It supports 128-bit and 256-bit keys with a 128-bit IV.
package sosemanuk

import (
	"encoding/binary"
	"errors"
)

const (
	// KeySize128 is the size of a 128-bit key in bytes
	KeySize128 = 16
	// KeySize256 is the size of a 256-bit key in bytes
	KeySize256 = 32
	// IVSize is the size of the IV in bytes
	IVSize = 16
	// LFSRLength is the number of LFSR stages
	LFSRLength = 10
)

var (
	// ErrInvalidKeySize is returned when the key size is not 128 or 256 bits
	ErrInvalidKeySize = errors.New("sosemanuk: invalid key size, must be 16 or 32 bytes")
	// ErrInvalidIVSize is returned when the IV size is not 128 bits
	ErrInvalidIVSize = errors.New("sosemanuk: invalid IV size, must be 16 bytes")
)

// Sosemanuk represents the state of the Sosemanuk stream cipher
type Sosemanuk struct {
	// LFSR state: s0 to s9
	s [LFSRLength]uint32
	// FSM state: R1 and R2
	r1, r2 uint32
	// Output buffer for 4 words
	out [4]uint32
	// Buffer position
	pos int
}

// alpha and alpha^-1 are the roots of the primitive polynomial
// x^32 + x^29 + x^25 + x^19 + x^14 + x^6 + x^1 + 1
// over GF(2^32) with the reduction polynomial x^32 + x^7 + x^3 + x^2 + 1
const (
	alpha  = 0x9b25919b
	alphaX = 0x4d965a4d // alpha^-1
)

// Serpent S-box S0
var sbox0 = [16]uint32{
	0x3, 0x8, 0xF, 0x1, 0xA, 0x6, 0x5, 0xB, 0xE, 0xD, 0x4, 0x2, 0x7, 0x0, 0x9, 0xC,
}

// Serpent S-box S1
var sbox1 = [16]uint32{
	0xF, 0xC, 0x2, 0x7, 0x9, 0x0, 0x5, 0xA, 0x1, 0xB, 0xE, 0x8, 0x6, 0xD, 0x3, 0x4,
}

// Serpent S-box S2
var sbox2 = [16]uint32{
	0x8, 0x6, 0x7, 0x9, 0x3, 0xC, 0xA, 0xF, 0xD, 0x1, 0xE, 0x4, 0x0, 0xB, 0x5, 0x2,
}

// Serpent S-box S3
var sbox3 = [16]uint32{
	0x0, 0xF, 0xB, 0x8, 0xC, 0x9, 0x6, 0x3, 0xD, 0x1, 0x2, 0x4, 0xA, 0x7, 0x5, 0xE,
}

// mulAlpha computes multiplication by alpha in GF(2^32)
func mulAlpha(x uint32) uint32 {
	if x&0x80000000 != 0 {
		return (x << 1) ^ 0x1b
	}
	return x << 1
}

// mulAlphaX computes multiplication by alpha^-1 in GF(2^32)
func mulAlphaX(x uint32) uint32 {
	if x&1 != 0 {
		return (x >> 1) ^ 0x800000d9
	}
	return x >> 1
}

// sboxApply applies the S-box transformation to a 32-bit word
func sboxApply(w uint32) uint32 {
	return (sbox0[w&0xf] |
		(sbox1[(w>>4)&0xf] << 4) |
		(sbox2[(w>>8)&0xf] << 8) |
		(sbox3[(w>>12)&0xf] << 12) |
		(sbox0[(w>>16)&0xf] << 16) |
		(sbox1[(w>>20)&0xf] << 20) |
		(sbox2[(w>>24)&0xf] << 24) |
		(sbox3[(w>>28)&0xf] << 28))
}

// sboxApplyInv applies the inverse S-box transformation to a 32-bit word
func sboxApplyInv(w uint32) uint32 {
	// Inverse S-boxes
	var invSbox0 = [16]uint32{0xd, 0x3, 0xb, 0x0, 0xa, 0x6, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xf, 0x9, 0x8, 0x2}
	var invSbox1 = [16]uint32{0x5, 0x8, 0x2, 0xe, 0xf, 0x6, 0xc, 0x3, 0xb, 0x4, 0x7, 0x9, 0x1, 0xd, 0xa, 0x0}
	var invSbox2 = [16]uint32{0xc, 0x9, 0xf, 0x4, 0xb, 0xe, 0x1, 0x2, 0x0, 0x3, 0x6, 0xd, 0x5, 0x8, 0xa, 0x7}
	var invSbox3 = [16]uint32{0x0, 0x9, 0xa, 0x7, 0xb, 0xe, 0x6, 0xd, 0x3, 0x5, 0xc, 0x2, 0x4, 0x8, 0xf, 0x1}

	return (invSbox0[w&0xf] |
		(invSbox1[(w>>4)&0xf] << 4) |
		(invSbox2[(w>>8)&0xf] << 8) |
		(invSbox3[(w>>12)&0xf] << 12) |
		(invSbox0[(w>>16)&0xf] << 16) |
		(invSbox1[(w>>20)&0xf] << 20) |
		(invSbox2[(w>>24)&0xf] << 24) |
		(invSbox3[(w>>28)&0xf] << 28))
}

// lfsrUpdate updates the LFSR state
func (s *Sosemanuk) lfsrUpdate() {
	// s(t+10) = alpha * s(t+9) + s(t+3) + alpha^-1 * s(t+0)
	newS := mulAlpha(s.s[9]) ^ s.s[3] ^ mulAlphaX(s.s[0])
	// Shift the LFSR
	for i := 0; i < LFSRLength-1; i++ {
		s.s[i] = s.s[i+1]
	}
	s.s[9] = newS
}

// fsmUpdate updates the FSM state and returns the output
func (s *Sosemanuk) fsmUpdate() uint32 {
	// R1(t+1) = s(t+1) + R2(t)
	r1New := s.s[1] + s.r2
	// R2(t+1) = s(t+8) * R1(t)
	r2New := s.s[8] * s.r1
	// Output = s(t+9) + R1(t)
	output := s.s[9] + s.r1

	s.r1 = r1New
	s.r2 = r2New

	return output
}

// generateOutput generates 4 words of output using the Serpent transformation
func (s *Sosemanuk) generateOutput() {
	var z [4]uint32

	// Generate 4 FSM outputs
	for i := 0; i < 4; i++ {
		z[i] = s.fsmUpdate()
		s.lfsrUpdate()
	}

	// Apply Serpent transformation
	// The transformation is: (z0, z1, z2, z3) -> (y0, y1, y2, y3)
	// where y = S(z) with a specific linear transformation
	s.out[0] = sboxApply(z[0])
	s.out[1] = sboxApply(z[1])
	s.out[2] = sboxApply(z[2])
	s.out[3] = sboxApply(z[3])

	// Apply linear transformation (Serpen-like)
	t0 := s.out[0]
	t1 := s.out[1]
	t2 := s.out[2]
	t3 := s.out[3]

	s.out[0] = t0 ^ t1 ^ t2
	s.out[1] = t1 ^ t2 ^ t3
	s.out[2] = t0 ^ t1 ^ t3
	s.out[3] = t0 ^ t2 ^ t3

	s.pos = 0
}

// keySchedule performs the key schedule for 128-bit or 256-bit keys
func (s *Sosemanuk) keySchedule(key []byte) error {
	keyLen := len(key)
	if keyLen != KeySize128 && keyLen != KeySize256 {
		return ErrInvalidKeySize
	}

	// Convert key to words
	var k [8]uint32
	for i := 0; i < keyLen/4; i++ {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}

	// Initialize LFSR using the key
	// For 128-bit key: use k0-k3, k4-k7 are derived
	// For 256-bit key: use k0-k7 directly
	if keyLen == KeySize128 {
		// Extend 128-bit key to 256-bit equivalent
		k[4] = k[0] ^ k[1] ^ k[2] ^ k[3]
		k[5] = k[0] ^ k[2]
		k[6] = k[1] ^ k[3]
		k[7] = k[0] ^ k[1] ^ k[2]
	}

	// Initialize LFSR state
	s.s[0] = k[0]
	s.s[1] = k[1]
	s.s[2] = k[2]
	s.s[3] = k[3]
	s.s[4] = k[4]
	s.s[5] = k[5]
	s.s[6] = k[6]
	s.s[7] = k[7]
	s.s[8] = k[0] ^ k[4]
	s.s[9] = k[1] ^ k[5]

	// Initialize FSM
	s.r1 = 0
	s.r2 = 0

	return nil
}

// ivSetup initializes the cipher with the IV
func (s *Sosemanuk) ivSetup(iv []byte) error {
	if len(iv) != IVSize {
		return ErrInvalidIVSize
	}

	// Convert IV to words
	iv0 := binary.LittleEndian.Uint32(iv[0:4])
	iv1 := binary.LittleEndian.Uint32(iv[4:8])
	iv2 := binary.LittleEndian.Uint32(iv[8:12])
	iv3 := binary.LittleEndian.Uint32(iv[12:16])

	// Mix IV into the LFSR state
	s.s[0] ^= iv0
	s.s[1] ^= iv1
	s.s[2] ^= iv2
	s.s[3] ^= iv3
	s.s[4] ^= iv0
	s.s[5] ^= iv1
	s.s[6] ^= iv2
	s.s[7] ^= iv3
	s.s[8] ^= iv0 ^ iv1
	s.s[9] ^= iv2 ^ iv3

	// Run the cipher for 32 iterations to initialize
	for i := 0; i < 32; i++ {
		s.fsmUpdate()
		s.lfsrUpdate()
	}

	// Generate initial output
	s.generateOutput()

	return nil
}

// New creates a new Sosemanuk cipher instance with the given key and IV
func New(key, iv []byte) (*Sosemanuk, error) {
	s := &Sosemanuk{}
	if err := s.keySchedule(key); err != nil {
		return nil, err
	}
	if err := s.ivSetup(iv); err != nil {
		return nil, err
	}
	return s, nil
}

// NextWord returns the next 32-bit word from the keystream
func (s *Sosemanuk) NextWord() uint32 {
	if s.pos >= 4 {
		s.generateOutput()
	}
	word := s.out[s.pos]
	s.pos++
	return word
}

// NextBytes fills the provided slice with keystream bytes
func (s *Sosemanuk) NextBytes(dst []byte) {
	for i := 0; i < len(dst); i += 4 {
		word := s.NextWord()
		if i+4 <= len(dst) {
			binary.LittleEndian.PutUint32(dst[i:], word)
		} else {
			// Handle remaining bytes
			for j := 0; i+j < len(dst); j++ {
				dst[i+j] = byte(word >> (j * 8))
			}
		}
	}
}

// XORKeyStream XORs the keystream with the input and writes to dst
func (s *Sosemanuk) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		return
	}

	for i := 0; i < len(src); i += 4 {
		word := s.NextWord()
		if i+4 <= len(src) {
			srcWord := binary.LittleEndian.Uint32(src[i:])
			dstWord := srcWord ^ word
			binary.LittleEndian.PutUint32(dst[i:], dstWord)
		} else {
			// Handle remaining bytes
			for j := 0; i+j < len(src); j++ {
				dst[i+j] = src[i+j] ^ byte(word>>(j*8))
			}
		}
	}
}

// Encrypt encrypts the plaintext using the cipher
func (s *Sosemanuk) Encrypt(plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	s.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// Decrypt decrypts the ciphertext using the cipher
// Note: For stream ciphers, decryption is the same as encryption
func (s *Sosemanuk) Decrypt(ciphertext []byte) []byte {
	return s.Encrypt(ciphertext)
}

// Reset resets the cipher state for reuse with the same key but different IV
func (s *Sosemanuk) Reset(key, iv []byte) error {
	if err := s.keySchedule(key); err != nil {
		return err
	}
	return s.ivSetup(iv)
}

// KeyStream generates n bytes of keystream
func (s *Sosemanuk) KeyStream(n int) []byte {
	keystream := make([]byte, n)
	s.NextBytes(keystream)
	return keystream
}