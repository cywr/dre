#!/bin/bash

# Clear all app data (cache, shared preferences, databases, files)
# Usage: ./clear_app.sh <app-package-name>

if [ $# -eq 0 ]; then
    echo "Usage: pnpm run clear <app-package-name>"
    echo "Example: pnpm run clear com.example.app"
    exit 1
fi

PACKAGE="$1"

echo "Clearing data for $PACKAGE..."
OUTPUT=$(adb shell pm clear "$PACKAGE" 2>&1)

if echo "$OUTPUT" | grep -q "Success"; then
    echo "Cleared all data for $PACKAGE"
else
    echo "Failed to clear data: $OUTPUT"
    exit 1
fi
