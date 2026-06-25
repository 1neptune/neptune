# Neptune - Disk-Scan Encryption Feature

## Overview
- **Summary**: Implement automatic disk scanning for encrypt and decrypt commands. When --input and --output are not specified, the program will automatically traverse all disks (Windows) or root directories (Linux) and process files matching the mandatory --include pattern.
- **Purpose**: Enable bulk encryption/decryption across entire storage volumes without manually specifying each path, while ensuring precise file filtering through mandatory include patterns.
- **Target Users**: Users who need to encrypt/decrypt specific file types across entire systems or multiple drives.

## Goals
- [ ] When --input and --output are not specified, encrypt/decrypt automatically scans all disks/root directories
- [ ] Default parameters: --force, --remove-source, --recursive, --timeout, --chunk-size, --parallel
- [ ] --include parameter is mandatory when --input is not specified
- [ ] Cross-platform compatibility: Windows (all disks), Linux (root directory)
- [ ] Encrypted files stay in place (same directory) with .ntp extension
- [ ] Decrypted files stay in place (same directory) with .ntp extension removed

## Non-Goals (Out of Scope)
- [ ] GUI interface for disk selection
- [ ] File size limits during bulk operations
- [ ] Progress tracking across multiple disks

## Background & Context
- Current implementation requires explicit --input parameter
- Users need to process files across multiple drives without specifying each path
- Need to ensure security by requiring --include pattern to prevent accidental data loss
- Cross-platform disk enumeration requires OS-specific implementation

## Functional Requirements
- **FR-1**: When --input is empty, automatically scan all disks (Windows) or root directories (Linux)
- **FR-2**: When --input is empty, --include parameter becomes mandatory
- **FR-3**: When --input is empty, set default values: --force=true, --remove-source=true, --recursive=true, --timeout=30, --chunk-size=64KB, --parallel=4
- **FR-4**: Encrypt files in-place (same directory) with .ntp extension when --output is empty
- **FR-5**: Decrypt files in-place (same directory) removing .ntp extension when --output is empty
- **FR-6**: Cross-platform disk enumeration supporting Windows and Linux

## Non-Functional Requirements
- **NFR-1**: Memory cleanup after operations (keys, URLs, encryption data)
- **NFR-2**: Error handling for inaccessible directories
- **NFR-3**: Warning before starting bulk operations
- **NFR-4**: Respect system permissions and skip inaccessible files

## Constraints
- **Technical**: Windows uses GetLogicalDriveStrings API, Linux uses / mount point
- **Business**: Must prevent accidental encryption of system files through --include filter
- **Dependencies**: Uses existing encryption/decryption infrastructure

## Assumptions
- [ ] User has appropriate permissions to read/write files on scanned disks
- [ ] --include pattern will filter out system and sensitive files
- [ ] Users understand the risks of bulk operations

## Acceptance Criteria

### AC-1: Auto-detect disks on Windows
- **Given**: Running on Windows without --input
- **When**: Executing neptune encrypt --include *.pdf --public-key key --private-key key
- **Then**: Program detects all logical drives (C:, D:, E:, etc.) and processes matching files
- **Verification**: `programmatic`

### AC-2: Auto-detect root on Linux
- **Given**: Running on Linux without --input
- **When**: Executing neptune encrypt --include *.pdf --public-key key --private-key key
- **Then**: Program scans / directory and processes matching files
- **Verification**: `programmatic`

### AC-3: --include mandatory when no --input
- **Given**: Running without --input
- **When**: Executing neptune encrypt without --include
- **Then**: Program returns error requiring --include parameter
- **Verification**: `programmatic`

### AC-4: Default parameters applied
- **Given**: Running without --input
- **When**: Executing neptune encrypt --include *.pdf --public-key key --private-key key
- **Then**: Default parameters (--force, --remove-source, --recursive, --timeout, --chunk-size, --parallel) are automatically applied
- **Verification**: `programmatic`

### AC-5: In-place encryption
- **Given**: File exists at /path/to/file.pdf
- **When**: Encrypting with --include *.pdf and no --output
- **Then**: File is encrypted to /path/to/file.pdf.ntp and original is removed
- **Verification**: `programmatic`

### AC-6: In-place decryption
- **Given**: Encrypted file exists at /path/to/file.pdf.ntp
- **When**: Decrypting with --include *.ntp and no --output
- **Then**: File is decrypted to /path/to/file.pdf and encrypted version is removed
- **Verification**: `programmatic`

### AC-7: Error handling for inaccessible directories
- **Given**: Running bulk encryption
- **When**: Encountering permission-denied directories
- **Then**: Program logs warning and continues processing accessible files
- **Verification**: `programmatic`

## Open Questions
- [ ] Should we exclude system directories by default (e.g., Windows/System32, /proc, /sys)?
- [ ] What is the default value for --parallel in bulk mode?
- [ ] Should we add a confirmation prompt before starting bulk operations?