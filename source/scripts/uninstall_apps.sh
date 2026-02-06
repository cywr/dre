#!/bin/bash

# Uninstall all non-system apps (same filter as `pnpm apps`)
# Usage: pnpm run uninstall-apps

FILTER='com.android|com.google.android|com.dolby|com.caf|com.topjohnwu.magisk|com.cybersandeep.fridalauncher|com.tsng.hidemyapplist|org.lsposed.manager|icu.nullptr.applistdetector'

# Get package identifiers (last column), skip header/separator lines
PACKAGES=$(frida-ps -Uai --exclude-icons | grep -vE "$FILTER" | awk 'NR>2 {print $NF}')

if [ -z "$PACKAGES" ]; then
    echo "No apps to uninstall."
    exit 0
fi

COUNT=$(echo "$PACKAGES" | wc -l | tr -d ' ')
echo "Found $COUNT app(s) to uninstall:"
echo "$PACKAGES" | sed 's/^/  /'
echo ""
read -p "Uninstall all? [y/N] " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

for PKG in $PACKAGES; do
    echo "Uninstalling $PKG..."
    adb uninstall "$PKG"
done

echo "Done."
