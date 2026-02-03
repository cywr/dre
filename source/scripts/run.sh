#!/bin/bash

# Navigate to project root
cd "$(dirname "$0")/../.." || exit 1

# Check if app name is provided
if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh <app-package-name>"
    echo "Example: ./run.sh owasp.mstg.uncrackable1"
    exit 1
fi

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