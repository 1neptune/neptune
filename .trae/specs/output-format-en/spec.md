# English Output Format Standardization - Product Requirements Document

## Overview
- **Summary**: Change all outputs of Neptune encryption tool to pure English text format, remove all emoji icons, ensure output is beautiful, clear, and parseable
- **Purpose**: Ensure program output conforms to international standards, facilitate log parsing, automated testing, and cross-platform compatibility
- **Target Users**: All users of Neptune, especially enterprise users requiring automated integration and log analysis

## Goals
- [ ] Remove all emoji icons from print functions (✅, ❌, ⚠, ℹ, ❓)
- [ ] Change all Chinese outputs to English
- [ ] Unify output format using concise prefixes to identify message types
- [ ] Ensure beautiful output line breaks with strong readability
- [ ] Compile latest version and test all functional parameters

## Non-Goals (Out of Scope)
- [ ] Change program functional logic
- [ ] Add new features or parameters
- [ ] Modify encryption/decryption algorithms
- [ ] Change command-line parameter structure

## Background & Context
- Current print functions use emoji icons (✅, ❌, ⚠, ℹ, ❓), which may display abnormally in some terminal environments
- Secure delete module (secure_delete_*.go) contains Chinese output, which doesn't meet internationalization requirements
- Users need plain text output for log analysis and automated testing

## Functional Requirements
- **FR-1**: Modify PrintSuccess function - Remove ✅ icon, use "[SUCCESS]" prefix
- **FR-2**: Modify PrintError function - Remove ❌ icon, use "[ERROR]" prefix
- **FR-3**: Modify PrintWarning function - Remove ⚠ icon, use "[WARNING]" prefix
- **FR-4**: Modify PrintInfo function - Remove ℹ icon, use "[INFO]" prefix
- **FR-5**: Modify PrintQuestion function - Remove ❓ icon, use "[QUESTION]" prefix
- **FR-6**: Change Chinese output in secure_delete_windows.go to English
- **FR-7**: Change Chinese output in secure_delete_linux.go to English


- **NFR-1**: Output format shall be uniform - all messages use the same prefix format "[TYPE] message"
- **NFR-2**: Line breaks shall be beautiful - each message on a separate line, important information separated by blank lines
- **NFR-3**: Parsability - output shall be easy for script parsing and log analysis
- **NFR-4**: Compatibility - output shall display correctly in all terminal environments

## Constraints
- **Technical**: Go language, modify utils.go and secure delete module files
- **Business**: Maintain backward compatibility, don't change functional logic
- **Dependencies**: Depends on fmt and os packages

## Assumptions
- [ ] Users expect English output
- [ ] All outputs go through PrintInfo/PrintSuccess/PrintWarning/PrintError/PrintQuestion functions
- [ ] Secure delete module is the only module containing Chinese output

## Acceptance Criteria

### AC-1: Print Functions Remove Emoji Icons
- **Given**: Call any print function (PrintInfo, PrintSuccess, PrintWarning, PrintError, PrintQuestion)
- **When**: Function executes output
- **Then**: Output doesn't contain any emoji icons, uses text prefix identification
- **Verification**: programmatic

### AC-2: Secure Delete Module Output Changed to English
- **Given**: Execute secure delete operation
- **When**: Program runs on Windows/Linux platform
- **Then**: All output messages are in English with uniform format
- **Verification**: human-judgment

### AC-3: Output Format is Beautiful
- **Given**: Execute any encryption/decryption operation
- **When**: Program outputs execution logs
- **Then**: Output format is clear, line breaks are reasonable, easy to read
- **Verification**: human-judgment

### AC-4: Compilation and Testing
- **Given**: After modifications are complete
- **When**: Execute go build and functional tests
- **Then**: Compilation succeeds, all functional parameters are available
- **Verification**: programmatic

## Open Questions
- [ ] Do we need to add color support for different log levels (optional)?
- [ ] Do we need to add detailed/concise mode switching?
