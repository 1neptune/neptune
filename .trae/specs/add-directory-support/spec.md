# Neptune - Directory Encryption/Decryption Feature Spec

## Why
Users need to encrypt all files in an entire directory and its subdirectories, not just individual files.

## What Changes
- Add `--recursive` (or `-R`) option to `encrypt` and `decrypt` commands
- Support recursive encryption/decryption of all files in directories
- Maintain directory structure and rebuild it during decryption
- Add `--include` and `--exclude` options for file filtering

## Impact
- Modify cmd/neptune/cmd/encrypt.go and decrypt.go
- Add directory handling utility functions
- Update help documentation

## ADDED Requirements

### Requirement: Directory Encryption
The system shall support recursive encryption of all files in a directory.

#### Scenario: Encrypt Directory
- **WHEN** user executes encrypt command with directory path and `--recursive` option
- **THEN** system recursively encrypts all files in the directory while maintaining directory structure

### Requirement: Directory Decryption
The system shall support recursive decryption of all encrypted files in a directory.

#### Scenario: Decrypt Directory
- **WHEN** user executes decrypt command with directory path and `--recursive` option
- **THEN** system recursively decrypts all encrypted files in the directory and rebuilds original directory structure

### Requirement: File Filtering
The system shall support include/exclude patterns for specific file types.

#### Scenario: Filter Files
- **WHEN** user specifies `--include` or `--exclude` options
- **THEN** system only processes matching files
