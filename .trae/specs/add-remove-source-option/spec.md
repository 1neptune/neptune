# Neptune - Remove Source File Feature Spec

## Why
Users want to automatically delete original files after encryption to ensure sensitive data doesn't remain in plaintext.

## What Changes
- Add `--remove-source` (or `-r`) option to `encrypt` command
- After successful encryption, delete source files based on user option
- Add safety confirmation mechanism to prevent accidental deletion

## Impact
- Modify cmd/neptune/cmd/encrypt.go
- Affects encryption flow

## ADDED Requirements

### Requirement: Remove Source File Option
The system shall provide an option to delete source files.

#### Scenario: Encrypt and Delete Source File
- **WHEN** user executes encrypt command with `--remove-source` option
- **AND** encryption completes successfully
- **THEN** system deletes the source file

#### Scenario: Confirm Before Deletion (Interactive)
- **WHEN** user executes encrypt command with `--remove-source` option
- **AND** `--force` option is not specified
- **THEN** system prompts user to confirm deletion

## MODIFIED Requirements

### Requirement: Encrypt Command
The encrypt command should support the remove source file option.
