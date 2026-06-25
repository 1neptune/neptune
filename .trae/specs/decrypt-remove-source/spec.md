# Neptune - Remove Encrypted File After Decryption Feature Spec

## Why
Users want to automatically delete the original encrypted files (.ntp files) after decryption, symmetric to the `--remove-source` feature of the encrypt command.

## What Changes
- Add `--remove-source` parameter to decrypt command
- Modify `decryptSingleFile` function to support deleting source files after decryption
- Modify `decryptDirectory` function to support deleting source files after parallel decryption
- Need to close files before deletion (Windows limitation)

## Impact
- Affected specs: None
- Affected code:
  - `cmd/neptune/cmd/decrypt.go` - Add parameter and deletion logic

## ADDED Requirements

### Requirement: Remove Source File After Decryption
The system SHALL delete the original encrypted files (.ntp files) after successful decryption.

#### Scenario: Decrypt Single File and Remove Source
- **WHEN** user decrypts a file using `--remove-source` parameter
- **THEN** the original encrypted file is automatically deleted after successful decryption

#### Scenario: Decrypt Directory and Remove Source
- **WHEN** user decrypts a directory using `--remove-source` parameter
- **THEN** each encrypted file is automatically deleted after successful decryption

#### Scenario: Parallel Decryption and Remove Source
- **WHEN** user uses `--parallel` and `--remove-source` parameters
- **THEN** files are closed before deletion after successful decryption, avoiding Windows file locking issues
