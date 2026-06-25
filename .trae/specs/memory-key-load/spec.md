# Neptune - Memory-Only Key Loading and Input Parameter Specification

## Overview
- **Summary**: Modify Neptune encryption program to support memory-only key pair loading, remove temporary file approach, and restrict `--input` parameter to local files only
- **Purpose**: Improve security by keeping keys entirely in memory; clarify parameter responsibilities to avoid confusion
- **Target Users**: Users requiring higher security

## Goals
- Remove temporary file approach for loading key pairs
- Support key pair loading from HTTP/HTTPS URLs directly into memory
- `--input` parameter only supports local file paths, not URLs
- Add separate parameter for remote resource download

## Non-Goals (Out of Scope)
- Do not change existing local key file loading approach
- Do not change encryption/decryption algorithms

## Background & Context
Users want to improve security by keeping keys entirely in memory when loaded remotely, without writing to temporary files. They also want to clearly distinguish between local and remote inputs.

## Functional Requirements
- **FR-1**: Support loading private keys from HTTP/HTTPS URLs directly into memory
- **FR-2**: Support loading public keys from HTTP/HTTPS URLs directly into memory
- **FR-3**: `--input` parameter only accepts local file paths
- **FR-4**: Add `--remote-url` parameter for downloading remote resources
- **FR-5**: Remove URL support from `--input` parameter

## Non-Functional Requirements
- **NFR-1**: Keys are processed in memory, not written to disk
- **NFR-2**: Provide clear error prompts

## Constraints
- **Technical**: Use Go's io.Reader to load keys directly from HTTP responses

## Assumptions
- Users understand the security benefits of memory loading
- Users have access to remote key servers

## Acceptance Criteria

### AC-1: Memory-only Private Key Loading
- **Given**: User specifies HTTP/HTTPS URL as private key path
- **When**: Executing encryption/decryption command
- **Then**: Key is downloaded from remote server to memory, not written to temporary file
- **Verification**: `programmatic`

### AC-2: Memory-only Public Key Loading
- **Given**: User specifies HTTP/HTTPS URL as public key path
- **When**: Executing encryption command
- **Then**: Key is downloaded from remote server to memory, not written to temporary file
- **Verification**: `programmatic`

### AC-3: --input Only Supports Local Files
- **Given**: User specifies URL in `--input` parameter
- **When**: Executing command
- **Then**: Program reports error prompting correct parameter usage
- **Verification**: `programmatic`

### AC-4: Remote Resource Download
- **Given**: User uses `--remote-url` parameter
- **When**: Executing encryption command
- **Then**: Remote file is downloaded to memory and encrypted
- **Verification**: `programmatic`

## Open Questions
- [ ] Do we need to support remote resource decryption?
