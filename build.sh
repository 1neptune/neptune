#!/bin/bash

# Neptune Build Script for Linux/macOS
# Usage: ./build.sh [version]

VERSION=${1:-"1.0.0"}
BUILD_DIR="build"

echo "=== Neptune Build Script ==="
echo "Version: $VERSION"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Build for Linux (amd64)
echo "Building for Linux..."
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=$VERSION" -o "$BUILD_DIR/neptune-linux-amd64" ./cmd/neptune
if [ $? -ne 0 ]; then
    echo "Failed to build for Linux"
    exit 1
fi

# Build for macOS (amd64)
echo "Building for macOS..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.version=$VERSION" -o "$BUILD_DIR/neptune-darwin-amd64" ./cmd/neptune
if [ $? -ne 0 ]; then
    echo "Failed to build for macOS"
    exit 1
fi

# Build for Windows (amd64)
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.version=$VERSION" -o "$BUILD_DIR/neptune-windows-amd64.exe" ./cmd/neptune
if [ $? -ne 0 ]; then
    echo "Failed to build for Windows"
    exit 1
fi

echo ""
echo "=== Build Complete ==="
echo "Binaries created in $BUILD_DIR/"
ls -la "$BUILD_DIR/"