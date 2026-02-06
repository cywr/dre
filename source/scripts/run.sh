#!/bin/bash

# Navigate to project root
cd "$(dirname "$0")/../.." || exit 1

# Check if app name is provided
if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh <app-package-name>"
    echo "Example: ./run.sh owasp.mstg.uncrackable1"
    exit 1
fi

# Ensure frida native binding exists (prebuild-install can silently fail during pnpm install)
FRIDA_BINDING="node_modules/.pnpm/frida@*/node_modules/frida/build/frida_binding.node"
if ! ls $FRIDA_BINDING &> /dev/null; then
    echo "Frida native binding missing, downloading prebuild..."
    FRIDA_DIR=$(ls -d node_modules/.pnpm/frida@*/node_modules/frida 2>/dev/null | head -1)
    if [ -n "$FRIDA_DIR" ]; then
        (cd "$FRIDA_DIR" && npx prebuild-install --verbose)
    else
        echo "Frida package not found. Run pnpm install first."
        exit 1
    fi
fi

# Suppress ANR/crash dialogs during instrumentation
# Frida hook init blocks the main thread, triggering Android's watchdog
adb shell settings put global hide_error_dialogs 1

cleanup() {
  adb shell settings put global hide_error_dialogs 0
}
trap cleanup EXIT

echo "Building project..."
pnpm run build

# Run frida with the provided app name
echo "Running frida with app: $1"

# Try different ways to run frida
if command -v frida &> /dev/null; then
    # Global frida installation
    frida -U -f "$1" -l _build/index.js
elif pnpx frida --version &> /dev/null; then
    # Local frida via pnpx
    pnpx frida -U -f "$1" -l _build/index.js
elif npx frida --version &> /dev/null; then
    # Local frida via npx (fallback)
    npx frida -U -f "$1" -l _build/index.js
else
    echo "❌ Frida not found!"
    echo "Please install frida globally:"
    echo "  npm install -g @frida/tools"
    echo "  # or"
    echo "  pip install frida-tools"
    echo ""
    echo "Or run manually:"
    echo "  frida -U -f $1 -l _build/index.js"
    exit 1
fi