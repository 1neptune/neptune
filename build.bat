@echo off
setlocal enabledelayedexpansion

REM Neptune Build Script for Windows
REM Usage: build.bat [version]

set VERSION=%1
if "%VERSION%"=="" set VERSION=1.0.0
set BUILD_DIR=build

echo === Neptune Build Script ===
echo Version: %VERSION%
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Build for Windows (amd64)
echo Building for Windows...
go build -ldflags "-s -w -X main.version=%VERSION%" -o "%BUILD_DIR%\neptune-windows-amd64.exe" ./cmd/neptune
if %errorlevel% neq 0 (
    echo Failed to build for Windows
    exit /b 1
)

REM Build for Linux (amd64)
echo Building for Linux...
set GOOS=linux
set GOARCH=amd64
go build -ldflags "-s -w -X main.version=%VERSION%" -o "%BUILD_DIR%\neptune-linux-amd64" ./cmd/neptune
if %errorlevel% neq 0 (
    echo Failed to build for Linux
    exit /b 1
)

REM Build for macOS (amd64)
echo Building for macOS...
set GOOS=darwin
set GOARCH=amd64
go build -ldflags "-s -w -X main.version=%VERSION%" -o "%BUILD_DIR%\neptune-darwin-amd64" ./cmd/neptune
if %errorlevel% neq 0 (
    echo Failed to build for macOS
    exit /b 1
)

REM Reset environment variables
set GOOS=
set GOARCH=

echo.
echo === Build Complete ===
echo Binaries created in %BUILD_DIR%\
dir "%BUILD_DIR%"

endlocal