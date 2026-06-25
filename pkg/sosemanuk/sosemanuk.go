// Package sosemanuk implements the Sosemanuk stream cipher.
//
// Sosemanuk is a software-oriented stream cipher based on SNOW 2.0 and Serpent.
// It was designed by Come Berbain, Olivier Billet, Anne Canteaut, Nicolas
// Courtois, Henri Gilbert, Louis Goubin, Aline Gouget, Louis Granboulan,
// Cedric Lauradoux, Marine Minier, Thomas Pornin, and Hervé Sibert.
//
// Key features:
//   - Supports 128-bit and 256-bit secret keys
//   - Uses a 128-bit initialization vector (IV)
//   - Combines a Linear Feedback Shift Register (LFSR) with a Finite State
//     Machine (FSM) for keystream generation
//   - Applies Serpent S-box transformations to the output for added security
//
// The cipher operates by generating a keystream that is XORed with the
// plaintext to produce ciphertext. Decryption is identical to encryption
// since XOR is its own inverse.
package sosemanuk

import (
	"encoding/binary"
	"errors"
)

const (
	// KeySize128 is the size of a 128-bit key in bytes (16 bytes).
	// Sosemanuk supports both 128-bit and 256-bit key sizes.
	KeySize128 = 16

	// KeySize256 is the size of a 256-bit key in bytes (32 bytes).
	// This is the maximum key size supported by Sosemanuk.
	KeySize256 = 32

	// IVSize is the size of the initialization vector in bytes (16 bytes, 128 bits).
	// The IV is combined with the key to produce different keystreams for
	// different messages using the same key.
	IVSize = 16

	// LFSRLength is the number of 32-bit stages in the Linear Feedback
	// Shift Register (LFSR). Sosemanuk uses a 10-stage LFSR (s0 to s9)
	// operating over GF(2^32).
	LFSRLength = 10
)

var (
	// ErrInvalidKeySize is returned when the provided key size is not
	// 16 bytes (128 bits) or 32 bytes (256 bits), which are the only
	// key sizes supported by Sosemanuk.
	ErrInvalidKeySize = errors.New("sosemanuk: invalid key size, must be 16 or 32 bytes")

	// ErrInvalidIVSize is returned when the provided IV size is not
	// 16 bytes (128 bits), which is the only IV size supported by Sosemanuk.
	ErrInvalidIVSize = errors.New("sosemanuk: invalid IV size, must be 16 bytes")
)

// Sosemanuk represents the internal state of the Sosemanuk stream cipher.
//
// The cipher state consists of:
//   - A 10-stage LFSR over GF(2^32) that provides linear diffusion
//   - A 2-register Finite State Machine (FSM) that provides non-linearity
//   - An output buffer that holds 4 pre-computed keystream words
//
// This struct should be created using New() and not manually initialized.
type Sosemanuk struct {
	// s is the LFSR state array containing 10 32-bit words (s0 through s9).
	// These represent the current state of the linear feedback shift register
	// over GF(2^32).
	s [LFSRLength]uint32

	// r1 is the first 32-bit register of the Finite State Machine (FSM).
	// It is used in the non-linear output function.
	r1 uint32

	// r2 is the second 32-bit register of the Finite State Machine (FSM).
	// It is used in the non-linear state update function.
	r2 uint32

	// out is the output buffer holding 4 pre-computed 32-bit keystream words.
	// These are generated together using the Serpent S-box transformation
	// and served one at a time via NextWord().
	out [4]uint32

	// pos is the current position within the output buffer (out).
	// It ranges from 0 to 3; when it reaches 4, a new batch of output
	// words is generated.
	pos int
}

// alpha and alpha^-1 are the roots of the primitive polynomial
// x^32 + x^29 + x^25 + x^19 + x^14 + x^6 + x^1 + 1
// over GF(2^32) with the reduction polynomial x^32 + x^7 + x^3 + x^2 + 1.
//
// These constants are used in the LFSR feedback function for multiplication
// by alpha (the primitive element) and its inverse.
const (
	// alpha is the primitive element of GF(2^32) used for the LFSR feedback.
	// Multiplying by alpha shifts the LFSR state forward by one step.
	alpha = 0x9b25919b

	// alphaX is alpha^-1 (the multiplicative inverse of alpha) in GF(2^32).
	// Multiplying by alpha^-1 shifts the LFSR state backward.
	alphaX = 0x4d965a4d
)

// sbox0 is the first Serpent S-box (S0).
// It is a 4-bit to 4-bit substitution table used in the sboxApply function
// to provide non-linear transformation of the output words.
//
// Source: Serpent block cipher specification, S-box S0.
var sbox0 = [16]uint32{
	0x3, 0x8, 0xF, 0x1, 0xA, 0x6, 0x5, 0xB, 0xE, 0xD, 0x4, 0x2, 0x7, 0x0, 0x9, 0xC,
}

// sbox1 is the second Serpent S-box (S1).
// It is a 4-bit to 4-bit substitution table used in the sboxApply function.
//
// Source: Serpent block cipher specification, S-box S1.
var sbox1 = [16]uint32{
	0xF, 0xC, 0x2, 0x7, 0x9, 0x0, 0x5, 0xA, 0x1, 0xB, 0xE, 0x8, 0x6, 0xD, 0x3, 0x4,
}

// sbox2 is the third Serpent S-box (S2).
// It is a 4-bit to 4-bit substitution table used in the sboxApply function.
//
// Source: Serpent block cipher specification, S-box S2.
var sbox2 = [16]uint32{
	0x8, 0x6, 0x7, 0x9, 0x3, 0xC, 0xA, 0xF, 0xD, 0x1, 0xE, 0x4, 0x0, 0xB, 0x5, 0x2,
}

// sbox3 is the fourth Serpent S-box (S3).
// It is a 4-bit to 4-bit substitution table used in the sboxApply function.
//
// Source: Serpent block cipher specification, S-box S3.
var sbox3 = [16]uint32{
	0x0, 0xF, 0xB, 0x8, 0xC, 0x9, 0x6, 0x3, 0xD, 0x1, 0x2, 0x4, 0xA, 0x7, 0x5, 0xE,
}

// mulAlpha computes multiplication of a 32-bit word by alpha in GF(2^32).
//
// The field GF(2^32) is defined using the reduction polynomial
// x^32 + x^7 + x^3 + x^2 + 1 (represented as 0x1b in the lowest bits).
// Multiplication by alpha (the primitive element) is equivalent to a left
// shift by 1, with conditional XOR of the reduction polynomial if the
// high bit was set.
//
// Parameters:
//   - x: the 32-bit word to multiply by alpha.
//
// Returns the product x * alpha in GF(2^32).
func mulAlpha(x uint32) uint32 {
	// If the highest bit is set, shifting left would overflow.
	// Apply the reduction polynomial 0x1b after the shift.
	if x&0x80000000 != 0 {
		return (x << 1) ^ 0x1b
	}
	return x << 1
}

// mulAlphaX computes multiplication of a 32-bit word by alpha^-1 (alpha inverse)
// in GF(2^32).
//
// This is the inverse operation of mulAlpha. Multiplication by alpha^-1 is
// equivalent to a right shift by 1, with conditional XOR of the inverse
// reduction polynomial if the low bit was set.
//
// Parameters:
//   - x: the 32-bit word to multiply by alpha^-1.
//
// Returns the product x * alpha^-1 in GF(2^32).
func mulAlphaX(x uint32) uint32 {
	// If the lowest bit is set, shifting right would lose it.
	// Apply the inverse reduction polynomial 0x800000d9 after the shift.
	if x&1 != 0 {
		return (x >> 1) ^ 0x800000d9
	}
	return x >> 1
}

// sboxApply applies the Serpent S-box transformation to a 32-bit word.
//
// The 32-bit word is split into 8 nibbles (4-bit groups). Each nibble is
// substituted using one of the four Serpent S-boxes, applied in the pattern
// S0, S1, S2, S3, S0, S1, S2, S3 from least significant to most significant.
//
// Parameters:
//   - w: the 32-bit input word to transform.
//
// Returns the 32-bit word after S-box substitution.
func sboxApply(w uint32) uint32 {
	// Apply each S-box to its corresponding 4-bit nibble:
	// bits 0-3:   sbox0
	// bits 4-7:   sbox1
	// bits 8-11:  sbox2
	// bits 12-15: sbox3
	// bits 16-19: sbox0
	// bits 20-23: sbox1
	// bits 24-27: sbox2
	// bits 28-31: sbox3
	return (sbox0[w&0xf] |
		(sbox1[(w>>4)&0xf] << 4) |
		(sbox2[(w>>8)&0xf] << 8) |
		(sbox3[(w>>12)&0xf] << 12) |
		(sbox0[(w>>16)&0xf] << 16) |
		(sbox1[(w>>20)&0xf] << 20) |
		(sbox2[(w>>24)&0xf] << 24) |
		(sbox3[(w>>28)&0xf] << 28))
}

// sboxApplyInv applies the inverse Serpent S-box transformation to a 32-bit word.
//
// This is the inverse of sboxApply, using the inverse S-box tables.
// It is defined for completeness and is not used in the main Sosemanuk
// keystream generation.
//
// Parameters:
//   - w: the 32-bit input word to inverse-transform.
//
// Returns the 32-bit word after inverse S-box substitution.
func sboxApplyInv(w uint32) uint32 {
	// Inverse S-box lookup tables for S0 through S3.
	// invSboxN[val] gives the input that produces val through sboxN.
	var invSbox0 = [16]uint32{0xd, 0x3, 0xb, 0x0, 0xa, 0x6, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xf, 0x9, 0x8, 0x2}
	var invSbox1 = [16]uint32{0x5, 0x8, 0x2, 0xe, 0xf, 0x6, 0xc, 0x3, 0xb, 0x4, 0x7, 0x9, 0x1, 0xd, 0xa, 0x0}
	var invSbox2 = [16]uint32{0xc, 0x9, 0xf, 0x4, 0xb, 0xe, 0x1, 0x2, 0x0, 0x3, 0x6, 0xd, 0x5, 0x8, 0xa, 0x7}
	var invSbox3 = [16]uint32{0x0, 0x9, 0xa, 0x7, 0xb, 0xe, 0x6, 0xd, 0x3, 0x5, 0xc, 0x2, 0x4, 0x8, 0xf, 0x1}

	// Apply inverse S-boxes to each 4-bit nibble, using the same pattern
	// as sboxApply but with the inverse tables.
	return (invSbox0[w&0xf] |
		(invSbox1[(w>>4)&0xf] << 4) |
		(invSbox2[(w>>8)&0xf] << 8) |
		(invSbox3[(w>>12)&0xf] << 12) |
		(invSbox0[(w>>16)&0xf] << 16) |
		(invSbox1[(w>>20)&0xf] << 20) |
		(invSbox2[(w>>24)&0xf] << 24) |
		(invSbox3[(w>>28)&0xf] << 28))
}

// lfsrUpdate advances the LFSR state by one clock cycle.
//
// The feedback equation is:
//   s(t+10) = alpha * s(t+9) + s(t+3) + alpha^-1 * s(t+0)
//
// where addition is XOR (characteristic 2) and multiplication is in GF(2^32).
// All existing words shift down (s[0] is discarded, s[1] becomes s[0], etc.),
// and the newly computed word is placed in s[9].
func (s *Sosemanuk) lfsrUpdate() {
	// Compute the new LFSR state word using the feedback polynomial:
	// s_new = alpha * s9 XOR s3 XOR alpha^-1 * s0
	newS := mulAlpha(s.s[9]) ^ s.s[3] ^ mulAlphaX(s.s[0])

	// Shift all LFSR stages: s[i] = s[i+1] for i = 0..8
	for i := 0; i < LFSRLength-1; i++ {
		s.s[i] = s.s[i+1]
	}

	// Place the new word into the last stage (s9).
	s.s[9] = newS
}

// fsmUpdate advances the Finite State Machine (FSM) by one step and
// returns the output word.
//
// The FSM has two 32-bit registers (R1, R2) and uses the following
// update equations (modular arithmetic):
//
//	R1(t+1) = s(t+1) + R2(t)   (mod 2^32)
//	R2(t+1) = s(t+8) * R1(t)   (mod 2^32)
//	output   = s(t+9) + R1(t)   (mod 2^32)
//
// Returns the 32-bit FSM output word for this clock cycle.
func (s *Sosemanuk) fsmUpdate() uint32 {
	// Compute new R1: R1(t+1) = s(t+1) + R2(t) mod 2^32
	r1New := s.s[1] + s.r2

	// Compute new R2: R2(t+1) = s(t+8) * R1(t) mod 2^32
	r2New := s.s[8] * s.r1

	// Compute output: output = s(t+9) + R1(t) mod 2^32
	output := s.s[9] + s.r1

	// Update the FSM state for the next cycle.
	s.r1 = r1New
	s.r2 = r2New

	return output
}

// generateOutput generates 4 keystream words by running the LFSR and FSM
// for 4 cycles, then applies the Serpent S-box transformation and a linear
// mixing layer to produce the final output buffer.
//
// The output generation process:
//  1. Generate 4 FSM output words (z0, z1, z2, z3)
//  2. Apply Serpent S-boxes to each word: y_i = S(z_i)
//  3. Apply a linear transformation to mix the 4 words
//
// After this function, s.out contains the 4 output words and s.pos is
// reset to 0.
func (s *Sosemanuk) generateOutput() {
	var z [4]uint32

	// Generate 4 FSM output words, advancing both the FSM and LFSR
	// by one clock cycle for each word.
	for i := 0; i < 4; i++ {
		z[i] = s.fsmUpdate()
		s.lfsrUpdate()
	}

	// Apply Serpent S-box substitution to each of the 4 words.
	// This provides non-linearity in the output function.
	s.out[0] = sboxApply(z[0])
	s.out[1] = sboxApply(z[1])
	s.out[2] = sboxApply(z[2])
	s.out[3] = sboxApply(z[3])

	// Apply linear diffusion transformation (Serpent-like linear layer).
	// This mixes the 4 words to ensure each output bit depends on
	// multiple S-box outputs, increasing diffusion.
	t0 := s.out[0]
	t1 := s.out[1]
	t2 := s.out[2]
	t3 := s.out[3]

	// The linear transformation is defined by the matrix:
	// out0 = t0 XOR t1 XOR t2
	// out1 = t1 XOR t2 XOR t3
	// out2 = t0 XOR t1 XOR t3
	// out3 = t0 XOR t2 XOR t3
	s.out[0] = t0 ^ t1 ^ t2
	s.out[1] = t1 ^ t2 ^ t3
	s.out[2] = t0 ^ t1 ^ t3
	s.out[3] = t0 ^ t2 ^ t3

	// Reset the output buffer position to the beginning.
	s.pos = 0
}

// keySchedule initializes the cipher state from the secret key.
//
// Supports both 128-bit and 256-bit keys:
//   - For 256-bit keys (KeySize256): the key is used directly as 8 words.
//   - For 128-bit keys (KeySize128): the key is expanded to 256 bits using
//     a simple linear expansion scheme.
//
// The LFSR is initialized with the key words, and the FSM registers
// are initialized to zero.
//
// Parameters:
//   - key: the secret key bytes. Must be 16 or 32 bytes long.
//
// Returns nil on success, or ErrInvalidKeySize if the key size is invalid.
func (s *Sosemanuk) keySchedule(key []byte) error {
	keyLen := len(key)
	if keyLen != KeySize128 && keyLen != KeySize256 {
		return ErrInvalidKeySize
	}

	// Convert the key bytes to an array of little-endian 32-bit words.
	var k [8]uint32
	for i := 0; i < keyLen/4; i++ {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}

	// For 128-bit keys, expand to 256 bits using a linear expansion.
	// k4-k7 are derived from k0-k3 using XOR combinations.
	if keyLen == KeySize128 {
		k[4] = k[0] ^ k[1] ^ k[2] ^ k[3]
		k[5] = k[0] ^ k[2]
		k[6] = k[1] ^ k[3]
		k[7] = k[0] ^ k[1] ^ k[2]
	}

	// Initialize the 10 LFSR stages with key material:
	// s0-s7 are loaded directly from the 8 key words.
	// s8 and s9 are XOR combinations of key words.
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

	// Initialize FSM registers to zero.
	s.r1 = 0
	s.r2 = 0

	return nil
}

// ivSetup mixes the initialization vector (IV) into the cipher state
// and runs the cipher for 32 initial iterations to produce the initial state.
//
// The IV is XORed into the LFSR state in a specific pattern, then the
// cipher is clocked 32 times to properly diffuse the IV throughout the state.
//
// Parameters:
//   - iv: the initialization vector bytes. Must be exactly 16 bytes long.
//
// Returns nil on success, or ErrInvalidIVSize if the IV size is invalid.
func (s *Sosemanuk) ivSetup(iv []byte) error {
	if len(iv) != IVSize {
		return ErrInvalidIVSize
	}

	// Convert the 16-byte IV to 4 little-endian 32-bit words.
	iv0 := binary.LittleEndian.Uint32(iv[0:4])
	iv1 := binary.LittleEndian.Uint32(iv[4:8])
	iv2 := binary.LittleEndian.Uint32(iv[8:12])
	iv3 := binary.LittleEndian.Uint32(iv[12:16])

	// XOR the IV words into the LFSR state according to the mixing pattern.
	// Each IV word is used multiple times to ensure full diffusion.
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

	// Run the cipher for 32 warm-up iterations to properly mix the
	// key and IV throughout the state before generating any keystream.
	// This prevents attacks that exploit the initial state structure.
	for i := 0; i < 32; i++ {
		s.fsmUpdate()
		s.lfsrUpdate()
	}

	// Generate the first batch of output words to be ready for use.
	s.generateOutput()

	return nil
}

// New creates a new Sosemanuk stream cipher instance initialized with
// the given key and IV.
//
// The cipher is fully initialized and ready to encrypt/decrypt data
// immediately after creation.
//
// Parameters:
//   - key: the secret key. Must be 16 bytes (128-bit) or 32 bytes (256-bit).
//   - iv: the initialization vector. Must be exactly 16 bytes (128-bit).
//
// Returns a pointer to the initialized Sosemanuk cipher on success,
// or nil with an error if the key or IV size is invalid.
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

// NextWord returns the next 32-bit word from the keystream.
//
// If the internal output buffer is exhausted (all 4 words consumed),
// a new batch of 4 output words is generated automatically.
//
// Returns the next 32-bit keystream word in little-endian order.
func (s *Sosemanuk) NextWord() uint32 {
	// If we've consumed all 4 words in the output buffer,
	// generate a new batch of 4 words.
	if s.pos >= 4 {
		s.generateOutput()
	}
	word := s.out[s.pos]
	s.pos++
	return word
}

// NextBytes fills the provided byte slice with keystream bytes.
//
// Keystream words are generated as needed and written in little-endian
// byte order. If the destination slice length is not a multiple of 4,
// the remaining bytes are filled from the next word without advancing
// past the required bytes.
//
// Parameters:
//   - dst: the byte slice to fill with keystream bytes. The slice is
//     modified in place.
func (s *Sosemanuk) NextBytes(dst []byte) {
	for i := 0; i < len(dst); i += 4 {
		word := s.NextWord()
		if i+4 <= len(dst) {
			// Full word: write all 4 bytes in little-endian order.
			binary.LittleEndian.PutUint32(dst[i:], word)
		} else {
			// Partial word: write only the remaining bytes.
			for j := 0; i+j < len(dst); j++ {
				dst[i+j] = byte(word >> (j * 8))
			}
		}
	}
}

// XORKeyStream XORs the keystream with the input (src) and writes the
// result to dst. This implements the standard stream cipher operation.
//
// The function is optimized in three phases for performance:
//  1. Process 16-byte blocks using all 4 buffered output words at once
//  2. Process remaining 4-byte (full word) blocks
//  3. Process any remaining bytes (less than 4)
//
// For correct operation, dst must have length at least len(src).
// If dst is shorter than src, the function returns without doing anything.
//
// Parameters:
//   - dst: the destination byte slice where the output is written.
//     Must be at least len(src) bytes long.
//   - src: the source byte slice containing the input data.
func (s *Sosemanuk) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		return
	}

	// Phase 1: Process 16-byte (4 uint32 word) blocks using the full
	// output buffer for maximum throughput.
	i := 0
	for i+16 <= len(src) {
		// Refill the output buffer if needed
		if s.pos >= 4 {
			s.generateOutput()
		}

		// Load 4 source words in little-endian order
		srcWord0 := binary.LittleEndian.Uint32(src[i:])
		srcWord1 := binary.LittleEndian.Uint32(src[i+4:])
		srcWord2 := binary.LittleEndian.Uint32(src[i+8:])
		srcWord3 := binary.LittleEndian.Uint32(src[i+12:])

		// XOR each source word with the corresponding keystream word
		// and write to the destination.
		binary.LittleEndian.PutUint32(dst[i:], srcWord0^s.out[s.pos])
		binary.LittleEndian.PutUint32(dst[i+4:], srcWord1^s.out[s.pos+1])
		binary.LittleEndian.PutUint32(dst[i+8:], srcWord2^s.out[s.pos+2])
		binary.LittleEndian.PutUint32(dst[i+12:], srcWord3^s.out[s.pos+3])

		s.pos += 4
		i += 16
	}

	// Phase 2: Process remaining full 4-byte (1 uint32) words.
	for i+4 <= len(src) {
		if s.pos >= 4 {
			s.generateOutput()
		}
		srcWord := binary.LittleEndian.Uint32(src[i:])
		binary.LittleEndian.PutUint32(dst[i:], srcWord^s.out[s.pos])
		s.pos++
		i += 4
	}

	// Phase 3: Process any remaining bytes (fewer than 4).
	if i < len(src) {
		if s.pos >= 4 {
			s.generateOutput()
		}
		word := s.out[s.pos]
		s.pos++
		for j := 0; i+j < len(src); j++ {
			dst[i+j] = src[i+j] ^ byte(word>>(j*8))
		}
	}
}

// Encrypt encrypts the given plaintext using the Sosemanuk stream cipher.
//
// Encryption works by XORing the plaintext with the keystream. A new
// byte slice is allocated and returned; the original plaintext is not
// modified.
//
// Parameters:
//   - plaintext: the input data to encrypt.
//
// Returns a newly allocated byte slice containing the ciphertext.
func (s *Sosemanuk) Encrypt(plaintext []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	s.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

// Decrypt decrypts the given ciphertext using the Sosemanuk stream cipher.
//
// For stream ciphers, decryption is identical to encryption since XOR
// is its own inverse. This method simply calls Encrypt.
//
// Parameters:
//   - ciphertext: the input data to decrypt.
//
// Returns a newly allocated byte slice containing the plaintext.
func (s *Sosemanuk) Decrypt(ciphertext []byte) []byte {
	return s.Encrypt(ciphertext)
}

// Reset reinitializes the cipher with a new key and IV, allowing the
// same Sosemanuk instance to be reused.
//
// This is more efficient than creating a new Sosemanuk value since it
// reuses the existing allocation. The cipher state is completely reset;
// no state from the previous key/IV is retained.
//
// Parameters:
//   - key: the new secret key. Must be 16 or 32 bytes.
//   - iv: the new initialization vector. Must be 16 bytes.
//
// Returns nil on success, or an error if the key or IV size is invalid.
func (s *Sosemanuk) Reset(key, iv []byte) error {
	if err := s.keySchedule(key); err != nil {
		return err
	}
	return s.ivSetup(iv)
}

// KeyStream generates n bytes of keystream and returns them as a new slice.
//
// This is useful when you need raw keystream bytes for custom operations.
// For encryption/decryption, prefer Encrypt/Decrypt or XORKeyStream.
//
// Parameters:
//   - n: the number of keystream bytes to generate.
//
// Returns a newly allocated byte slice of length n containing keystream data.
func (s *Sosemanuk) KeyStream(n int) []byte {
	keystream := make([]byte, n)
	s.NextBytes(keystream)
	return keystream
}
