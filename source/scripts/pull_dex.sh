#!/bin/bash

# Pull DEX files from Android device to local _build folder

# Navigate to project root
cd "$(dirname "$0")/../.." || exit 1

# Possible device paths in order of preference
POSSIBLE_PATHS=(
    "/sdcard/Download/dre_extractions"
    "/sdcard/Documents/dre_extractions"
    "/data/local/tmp/dre_extractions"
    "/sdcard/dre_extractions"
)

LOCAL_PATH="_build/dex_extractions"

echo "🔍 Checking for DEX files on device..."

# Check if adb is available
if ! command -v adb &> /dev/null; then
    echo "❌ adb command not found!"
    echo "Make sure Android SDK is installed and adb is in your PATH"
    exit 1
fi

# Check if device is connected
if ! adb get-state &> /dev/null; then
    echo "❌ No Android device connected!"
    echo "Make sure your device is connected via USB and USB debugging is enabled"
    exit 1
fi

echo "✅ Device connected: $(adb get-state)"

# Find extraction directory on device
DEVICE_PATH=""
for path in "${POSSIBLE_PATHS[@]}"; do
    if adb shell "test -d '$path'" 2>/dev/null; then
        DEVICE_PATH="$path"
        echo "📁 Found extraction directory: $DEVICE_PATH"
        break
    fi
done

if [ -z "$DEVICE_PATH" ]; then
    echo "ℹ️  No extractions directory found on device"
    echo "Checked paths:"
    for path in "${POSSIBLE_PATHS[@]}"; do
        echo "  - $path"
    done
    echo "Run your Frida script first to generate some DEX files"
    exit 0
fi

# List files in device extraction directory
echo "📁 Files found on device:"
dex_files=$(adb shell "ls '$DEVICE_PATH'/*.dex 2>/dev/null" | tr -d '\r')

if [ -z "$dex_files" ]; then
    echo "ℹ️  No DEX files found in $DEVICE_PATH"
    echo "Run your Frida script and trigger some Base64/Cipher operations"
    exit 0
fi

echo "$dex_files" | while read -r file; do
    if [ -n "$file" ]; then
        filename=$(basename "$file")
        size=$(adb shell "stat -c%s '$file'" 2>/dev/null | tr -d '\r')
        echo "  📄 $filename ($size bytes)"
    fi
done

# Create local extraction directory
mkdir -p "$LOCAL_PATH"

# Pull all DEX files from device
echo ""
echo "📥 Pulling DEX files to local machine..."
adb pull "$DEVICE_PATH/" "$LOCAL_PATH/"

if [ $? -eq 0 ]; then
    echo "✅ DEX files successfully copied to $LOCAL_PATH/"
    
    # List extracted files locally
    echo ""
    echo "📂 Local DEX files:"
    if ls "$LOCAL_PATH"/*.dex &> /dev/null; then
        ls -la "$LOCAL_PATH"/*.dex | while read -r line; do
            echo "  $line"
        done
    fi
    
    # Ask if user wants to clean device files
    echo ""
    read -p "🗑️  Remove DEX files from device? (y/N): " cleanup
    if [[ $cleanup =~ ^[Yy]$ ]]; then
        adb shell "rm -f '$DEVICE_PATH'/*.dex"
        echo "✅ Device files cleaned up"
    fi
    
else
    echo "❌ Failed to pull DEX files from device"
    exit 1
fi

echo ""
echo "🎉 DEX extraction complete!"
echo "Files are now available in: $LOCAL_PATH/"