# Neptune - Prevent Duplicate Encryption Feature Spec

## Overview
- **Summary**: Add duplicate encryption detection feature to Neptune encryption program to prevent secondary encryption of already encrypted files
- **Purpose**: Avoid user errors that cause data corruption, improve user experience and data security
- **Target Users**: Users who encrypt files with Neptune

## Goals
- Detect whether a file is already encrypted (.ntp format)
- Validate file format before encryption, reject duplicate encryption
- Provide clear error prompt messages
- Support batch detection during directory encryption

## Non-Goals (Out of Scope)
- Modify encryption algorithm itself
- Add file decryption validation (already handled in decryption flow)

## Background & Context
Users may accidentally encrypt already encrypted files again, causing data to be undecryptable. Detection logic needs to be added before the encryption flow starts.

## Functional Requirements
- **FR-1**: When encrypting a single file, detect if the file is in .ntp format (Neptune encrypted format)
- **FR-2**: When encrypting a directory, recursively detect all files for .ntp format
- **FR-3**: When an already encrypted file is detected, reject encryption and provide clear error prompt
- **FR-4**: Provide `--force-override` option to allow forced encryption (overwriting existing encrypted files)

## Non-Functional Requirements
- **NFR-1**: Detection logic must be fast, not affecting overall encryption performance
- **NFR-2**: Error prompt messages must be clear and understandable, guiding users to correct operations
- **NFR-3**: Detection should happen before actual encryption operation

## Constraints
- **Technical**: Need to parse Neptune encrypted file format header (1-byte version number + 32-byte public key + 16-byte nonce)
- **Dependencies**: Depends on existing file handling logic

## Assumptions
- Encrypted files all end with .ntp extension
- File header contains specific version identifier (0x01)

## Acceptance Criteria

### AC-1: Detect Already Encrypted Files
- **Given**: User attempts to encrypt a .ntp file
- **When**: Executing `neptune encrypt --input file.ntp --output ...`
- **Then**: Program detects file is already encrypted, outputs error message and exits
- **Verification**: `programmatic`

### AC-2: Skip Already Encrypted Files During Directory Encryption
- **Given**: User attempts to encrypt a directory containing .ntp files
- **When**: Executing `neptune encrypt --input dir/ --output ... --recursive`
- **Then**: Program skips .ntp files, only encrypts unencrypted files
- **Verification**: `programmatic`

### AC-3: Force Override Option
- **Given**: User explicitly specifies `--force-override` option
- **When**: Executing `neptune encrypt --input file.ntp --output ... --force-override`
- **Then**: Program allows secondary encryption of already encrypted files
- **Verification**: `programmatic`

### AC-4: Error Prompt Message
- **Given**: User attempts to encrypt an already encrypted file
- **When**: Executing encryption command
- **Then**: Program outputs clear error prompt explaining the file is already encrypted
- **Verification**: `human-judgment`

## Open Questions
- [ ] Do we need to support automatic detection of files with non-.ntp extensions but actually encrypted? (via file header detection)
