// Package utils provides common utility functions and types for the Neptune encryption tool.
// This package includes error handling, secure memory management, disk utilities,
// and other shared functionality used across the Neptune codebase.
package utils

import (
	"runtime"
	"sync"
)

// memoryCleanupMu is a mutex that protects all secure memory wipe operations.
// It ensures that concurrent secure wipe operations do not interfere with each
// other, and that memory is properly zeroed before being garbage collected.
var memoryCleanupMu sync.Mutex

// SecureZeroMemory securely overwrites a byte slice with zeros to prevent
// sensitive data from remaining in memory. This function is designed to
// securely erase cryptographic keys, passwords, and other sensitive data
// from memory after use, reducing the risk of data leakage through memory
// dumps or cold boot attacks.
//
// The function acquires a global mutex to prevent concurrent secure wipe
// operations and triggers a garbage collection cycle after zeroing to
// help ensure the memory is reclaimed.
//
// Parameters:
//   - data: The byte slice to zero out. If the slice is empty (len == 0),
//           the function returns immediately with no action taken.
func SecureZeroMemory(data []byte) {
	memoryCleanupMu.Lock()
	defer memoryCleanupMu.Unlock()

	// Early return for empty slices to avoid unnecessary work
	if len(data) == 0 {
		return
	}

	// Overwrite every byte in the slice with zero to erase sensitive data
	for i := range data {
		data[i] = 0
	}

	// Trigger garbage collection to help reclaim the zeroed memory
	runtime.GC()
}

// SecureWipeString securely wipes the contents of a string from memory.
// Since Go strings are immutable, this function converts the string to a
// rune slice, overwrites each rune with zero, then sets the original
// string pointer to an empty string. This helps prevent sensitive string
// data (such as passwords or passphrases) from lingering in memory.
//
// The function acquires a global mutex to prevent concurrent secure wipe
// operations and triggers a garbage collection cycle after wiping.
//
// Parameters:
//   - s: A pointer to the string to wipe. If s is nil or the string is
//        already empty, the function returns immediately with no action.
func SecureWipeString(s *string) {
	if s == nil || *s == "" {
		return
	}

	memoryCleanupMu.Lock()
	defer memoryCleanupMu.Unlock()

	// Convert string to mutable rune slice for in-place modification
	runes := []rune(*s)
	// Overwrite each rune with zero to erase the string data
	for i := range runes {
		runes[i] = 0
	}
	// Replace the original string with an empty string
	*s = ""

	// Trigger garbage collection to help reclaim the wiped memory
	runtime.GC()
}

// SecureWipeSlice securely wipes sensitive data from a slice of any
// supported type. It uses a type switch to handle different slice types:
//
//   - []byte:       Overwrites each byte with zero directly.
//   - []string:     Securely wipes each string element using SecureWipeString.
//   - []interface{}: Recursively wipes each element using SecureWipeSlice.
//
// The function acquires a global mutex to prevent concurrent secure wipe
// operations and triggers a garbage collection cycle after wiping.
//
// Parameters:
//   - slice: The slice to wipe, passed as an empty interface. The function
//            handles the type assertion internally. If the type is not one
//            of the supported slice types, the function does nothing.
func SecureWipeSlice(slice interface{}) {
	memoryCleanupMu.Lock()
	defer memoryCleanupMu.Unlock()

	// Type switch to handle different slice types appropriately
	switch v := slice.(type) {
	case []byte:
		// Direct byte slice: zero out each byte
		for i := range v {
			v[i] = 0
		}
	case []string:
		// String slice: securely wipe each individual string
		for i := range v {
			SecureWipeString(&v[i])
		}
	case []interface{}:
		// Interface slice: recursively wipe each element
		for i := range v {
			SecureWipeSlice(v[i])
		}
	}

	// Trigger garbage collection to help reclaim the wiped memory
	runtime.GC()
}
