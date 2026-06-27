# Build Rules

## Coding Rules
- Code comments must be provided
- Console output must be in English
- Log output must be in English
- High cohesion and low coupling, each function should only be responsible for one feature
- High maintainability with clear code structure, detailed comments, and standardized naming
- Compliance with Go language coding standards
- High code quality, avoiding duplicate code and redundancy
- High code extensibility, considering future feature expansion
- Low time complexity and low space complexity
- Performance optimization, avoiding memory leaks
- All functional code files must have detailed English comments, including package-level comments, function comments with parameter and return value descriptions, and inline comments for complex logic

## Go Build Rules
When modifying functional code, consider compatibility with Windows and Linux platforms.

After each code modification, when building the program, first clean up previous build files, then perform a new build for both Windows and Linux, placing the output in the build directory.
- Windows -> neptune.exe
- Linux -> neptune

Use `go build -ldflags="-s -w -H windowsgui"` to reduce executable file size.

### Windows Code Signing Rules
After building neptune.exe for Windows, the executable must be digitally signed using signtool:

```bash
# Sign the executable with SHA256 digest algorithm and timestamp
signtool sign /tr http://timestamp.digicert.com /td SHA256 /fd SHA256 /f "E:\neptune\neptune.pfx" /p Neptune@2026 "E:\neptune\build\neptune.exe"

# Verify the digital signature
signtool verify /pa /v "E:\neptune\build\neptune.exe"
```

- PFX certificate file: `E:\neptune\neptune.pfx`
- Certificate password: `Neptune@2026`
- Timestamp server: `http://timestamp.digicert.com`
- Digest algorithm: SHA256
- Verification must pass before the build is considered complete



## Code Testing Rules
- After each code modification, perform new feature tests to ensure the new features work correctly.
- After each test, clean up test file cases to ensure a clean environment.

## Version Update Rules
- Each time, modify the --version option to ensure the version number matches the code version.
- Each time, update README.md according to the actual code changes to ensure the version number matches the code version.