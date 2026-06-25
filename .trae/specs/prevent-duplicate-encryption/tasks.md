# Neptune - Prevent Duplicate Encryption Feature - Implementation Plan

## [x] Task 1: Add file format detection function
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - Add function in `internal/utils/utils.go` to detect if a file is in Neptune encrypted format
  - Detection logic: Check if file extension is .ntp, or check if file header contains Neptune format identifier
- **Acceptance Criteria Addressed**: AC-1, AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: Detection of .ntp file returns true
  - `programmatic` TR-1.2: Detection of non-.ntp file returns false
- **Notes**: Need to handle cases where file doesn't exist or can't be read

## [x] Task 2: Modify encrypt command to add duplicate encryption detection
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - Modify `cmd/encrypt.go` to add duplicate encryption detection logic
  - Check if target file is already encrypted before encryption
  - Add `--force-override` option to allow forced encryption
- **Acceptance Criteria Addressed**: AC-1, AC-3, AC-4
- **Test Requirements**:
  - `programmatic` TR-2.1: Encryption of .ntp file is rejected with error
  - `programmatic` TR-2.2: Encryption is allowed when --force-override option is used
  - `human-judgment` TR-2.3: Error prompt message is clear and understandable
- **Notes**: Need to add new command-line parameter

## [x] Task 3: Modify directory encryption logic
- **Priority**: P0
- **Depends On**: Task 2
- **Description**: 
  - Modify directory encryption logic to skip already encrypted .ntp files
  - Add log output for skipped files
- **Acceptance Criteria Addressed**: AC-2, AC-4
- **Test Requirements**:
  - `programmatic` TR-3.1: Directory encryption skips .ntp files
  - `human-judgment` TR-3.2: Output list of skipped files
- **Notes**: Need to maintain existing include/exclude filtering logic

## [ ] Task 4: Add unit tests
- **Priority**: P1
- **Depends On**: Task 1, Task 2, Task 3
- **Description**: 
  - Write unit tests for newly added functions
  - Test various boundary cases
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `programmatic` TR-4.1: All test cases pass
- **Notes**: Tests should cover normal and abnormal cases

## [ ] Task 5: Update README.md
- **Priority**: P2
- **Depends On**: Task 2
- **Description**: 
  - Update documentation to explain new `--force-override` option
  - Add description of duplicate encryption detection feature
- **Acceptance Criteria Addressed**: AC-4
- **Test Requirements**:
  - `human-judgment` TR-5.1: Documentation clearly explains new feature
- **Notes**: Documentation update should be concise and clear
