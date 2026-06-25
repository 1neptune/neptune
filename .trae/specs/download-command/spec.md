# Neptune - Standalone Download Command Spec

## Overview
- **Summary**: Add a standalone `download` command for downloading files from remote servers
- **Purpose**: Separate download functionality from encryption functionality, allowing users to use download independently
- **Target Users**: Users who need to download remote resources

## Goals
- Add standalone `download` command
- Support multiple `--remote-url` parameters for batch download
- Support `--output` parameter to specify output directory
- Remove `--remote-url` parameter from `encrypt` command

## Non-Goals (Out of Scope)
- Do not change existing encryption/decryption logic

## Functional Requirements
- **FR-1**: Add standalone `download` command
- **FR-2**: `download` command supports `--remote-url` parameter (can be used multiple times)
- **FR-3**: `download` command supports `--output` parameter to specify output directory
- **FR-4**: Remove `--remote-url` parameter from `encrypt` command

## Acceptance Criteria

### AC-1: Standalone Download Command
- **Given**: User executes `neptune download` command
- **When**: Using `--remote-url` and `--output` parameters
- **Then**: File is downloaded to specified directory
- **Verification**: `programmatic`

### AC-2: Batch Download
- **Given**: User provides multiple `--remote-url` parameters
- **When**: Executing download command
- **Then**: All files are downloaded to specified directory
- **Verification**: `programmatic`

## Open Questions
- [ ] Do we need to add other download options (such as timeout, proxy, etc.)?
