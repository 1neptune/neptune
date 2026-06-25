# Neptune - Memory-Only Key Loading - Implementation Plan

## [x] Task 1: Add functions to load keys from byte data in curve25519 package
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - Add `LoadKeyPairFromBytes()` function
  - Add `LoadPublicKeyFromBytes()` function
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: Can load key pair from byte data
  - `programmatic` TR-1.2: Can load public key from byte data
- **Notes**: Need to handle different encoding formats

## [ ] Task 2: Modify utils package to add HTTP download to bytes function
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - Use existing `DownloadBytes()` function
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-2.1: Can download data from URL to memory
- **Notes**: Already completed in previous implementation

## [ ] Task 3: Modify encrypt.go to support memory-only key loading
- **Priority**: P0
- **Depends On**: Task 1, Task 2
- **Description**: 
  - Modify key loading logic to load directly from HTTP response into memory
  - Remove temporary file related code
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `programmatic` TR-3.1: Supports memory-only private key loading from URL
  - `programmatic` TR-3.2: Supports memory-only public key loading from URL
  - `programmatic` TR-3.3: --input parameter does not accept URLs

## [ ] Task 4: Modify decrypt.go to support memory-only key loading
- **Priority**: P0
- **Depends On**: Task 1, Task 2
- **Description**: 
  - Modify key loading logic to load directly from HTTP response into memory
  - Remove temporary file related code
- **Acceptance Criteria Addressed**: AC-1, AC-3
- **Test Requirements**:
  - `programmatic` TR-4.1: Supports memory-only private key loading from URL
  - `programmatic` TR-4.2: --input parameter does not accept URLs

## [ ] Task 5: Add --remote-url parameter
- **Priority**: P1
- **Depends On**: Task 3
- **Description**: 
  - Add `--remote-url` parameter for downloading remote resources
- **Acceptance Criteria Addressed**: AC-4
- **Test Requirements**:
  - `programmatic` TR-5.1: Supports downloading and encrypting files via --remote-url

## [ ] Task 6: Update documentation
- **Priority**: P2
- **Depends On**: All
- **Description**: 
  - Update README.md to document new features
- **Acceptance Criteria Addressed**: All
- **Test Requirements**:
  - `human-judgment` TR-6.1: Documentation clearly explains new features
