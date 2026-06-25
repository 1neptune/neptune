# Neptune - Disk-Scan Encryption Feature - Implementation Plan

## [x] Task 1: Add disk enumeration utility functions (cross-platform)
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - Create platform-specific disk enumeration functions in utils package
  - Windows: Use syscall to call GetLogicalDriveStrings
  - Linux: Return "/" as root directory
  - Add function `GetAllDisks()` that returns list of drive paths
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: GetAllDisks() returns valid drive paths on Windows
  - `programmatic` TR-1.2: GetAllDisks() returns "/" on Linux
  - `human-judgement` TR-1.3: Code handles errors gracefully when disk access fails

## [x] Task 2: Modify encrypt command for disk-scan mode
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - Modify encrypt.go to detect when --input is empty
  - When --input is empty, require --include parameter
  - Set default parameters: --force=true, --remove-source=true, --recursive=true, --timeout=30, --chunk-size=64KB, --parallel=4
  - Iterate through all disks and encrypt matching files in-place
- **Acceptance Criteria Addressed**: AC-3, AC-4, AC-5
- **Test Requirements**:
  - `programmatic` TR-2.1: Encrypt without --input requires --include
  - `programmatic` TR-2.2: Default parameters are applied when no --input
  - `programmatic` TR-2.3: Files are encrypted in-place with .ntp extension
  - `human-judgement` TR-2.4: Error messages are clear and helpful

## [x] Task 3: Modify decrypt command for disk-scan mode
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - Modify decrypt.go to detect when --input is empty
  - When --input is empty, require --include parameter
  - Set default parameters: --force=true, --remove-source=true, --recursive=true, --timeout=30, --chunk-size=64KB, --parallel=4
  - Iterate through all disks and decrypt matching files in-place
- **Acceptance Criteria Addressed**: AC-3, AC-4, AC-6
- **Test Requirements**:
  - `programmatic` TR-3.1: Decrypt without --input requires --include
  - `programmatic` TR-3.2: Default parameters are applied when no --input
  - `programmatic` TR-3.3: Files are decrypted in-place with .ntp extension removed
  - `human-judgement` TR-3.4: Error messages are clear and helpful

## [x] Task 4: Add error handling for inaccessible directories
- **Priority**: P1
- **Depends On**: Tasks 2, 3
- **Description**: 
  - Add error handling to skip inaccessible directories with warning
  - Log warnings for permission-denied paths
  - Continue processing other accessible directories
- **Acceptance Criteria Addressed**: AC-7
- **Test Requirements**:
  - `programmatic` TR-4.1: Permission-denied directories trigger warning but don't stop processing
  - `human-judgement` TR-4.2: Warning messages clearly indicate which directories were skipped

## [ ] Task 5: Add warning before starting bulk operations
- **Priority**: P1
- **Depends On**: Tasks 2, 3
- **Description**: 
  - Display warning message before starting disk-scan mode
  - Show number of disks and include patterns
  - Give user a chance to cancel (optional)
- **Acceptance Criteria Addressed**: NFR-3
- **Test Requirements**:
  - `human-judgement` TR-5.1: Warning message is displayed before bulk operation starts
  - `human-judgement` TR-5.2: Warning includes disk count and include patterns

## [x] Task 6: Update documentation
- **Priority**: P2
- **Depends On**: Tasks 2, 3
- **Description**: 
  - Update README.md with new disk-scan mode usage examples
  - Document default parameters and mandatory --include requirement
- **Acceptance Criteria Addressed**: N/A
- **Test Requirements**:
  - `human-judgement` TR-6.1: README includes disk-scan mode documentation
  - `human-judgement` TR-6.2: Examples show correct usage with --include