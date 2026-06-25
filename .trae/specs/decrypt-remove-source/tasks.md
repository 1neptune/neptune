# Tasks

- [ ] Task 1: Add --remove-source parameter to decrypt command
  - [ ] SubTask 1.1: Add decryptRemoveSource variable
  - [ ] SubTask 1.2: Register --remove-source parameter in init function
  - [ ] SubTask 1.3: Update command help documentation

- [ ] Task 2: Modify decryptSingleFile to support source file deletion
  - [ ] SubTask 2.1: Close input file after successful decryption
  - [ ] SubTask 2.2: Delete source file based on --remove-source parameter
  - [ ] SubTask 2.3: Handle deletion failures (warn but don't interrupt)

- [ ] Task 3: Modify decryptDirectory to support source file deletion
  - [ ] SubTask 3.1: Close input files after successful decryption
  - [ ] SubTask 3.2: Delete source files based on --remove-source parameter
  - [ ] SubTask 3.3: Handle deletion failures (warn but don't interrupt)

- [ ] Task 4: Update README.md documentation
  - [ ] SubTask 4.1: Add --remove-source to decrypt parameter table
  - [ ] SubTask 4.2: Add usage examples

- [ ] Task 5: Compilation and testing
  - [ ] SubTask 5.1: Compile updated version
  - [ ] SubTask 5.2: Test decryption deletion feature

# Task Dependencies
- Task 2 depends on Task 1
- Task 3 depends on Task 1
- Task 4 depends on Task 1-3
- Task 5 depends on Task 1-4
