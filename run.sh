#!/bin/bash

# Check if app name is provided
if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh <app-package-name>"
    echo "Example: ./run.sh owasp.mstg.uncrackable1"
    exit 1
fi

# Build the project (check if _build/index.js exists and is newer than source)
if [ ! -f "_build/index.js" ] || [ "agent/index.ts" -nt "_build/index.js" ]; then
    echo "Building project..."
    npm run build
else
    echo "Project already built, skipping..."
fi

# Run frida with the provided app name
echo "Running frida with app: $1"

# Try different ways to run frida
if command -v frida &> /dev/null; then
    # Global frida installation
    frida -U -f "$1" -l _build/index.js
elif npx frida --version &> /dev/null; then
    # Local frida via npx
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