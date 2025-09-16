# DRE - Frida Anti-Emulation Bypass

Dynamic Reverse Engineering tool with configurable logging system.

## Prerequisites

You need to install Frida globally:
```bash
# Install frida-tools globally
pnpm add -g @frida/tools
# or
npm install -g @frida/tools
# or
pip install frida-tools
```

## Quick Commands

### Run Any App (Generic)
```bash
# Using the shell script directly (RECOMMENDED)
./run.sh <package-name>

# Using pnpm/npm with shell script
pnpm run start <package-name>
# or
npm run start <package-name>

# Manual command (if scripts don't work)
pnpm run build
frida -U -f <package-name> -l _build/index.js
```

### Examples
```bash
./run.sh com.example.myapp
```

## DEX File Extraction

The framework automatically detects and extracts DEX files that pass through Base64 or Cipher operations. When DEX files are detected, they are:

- **Automatically identified** by DEX magic bytes and version validation
- **Saved to device** in a writable directory (e.g., `/sdcard/Download/dre_extractions/`)
- **Pulled to local machine** using adb to `_build/dex_extractions/`
- **Named descriptively** with context, operation, timestamp, and version

### DEX Extraction Workflow

1. **Run your Frida script** to generate DEX files on the device:
```bash
./run.sh com.example.app
```

2. **Pull DEX files** from device to your Mac:
```bash
pnpm run pull-dex
# or
npm run pull-dex
```

### Extracted File Format
Files are saved as: `dex_{context}_{operation}_{timestamp}_v{version}.dex`

Example: `dex_Base64_decode_2024-09-16T10-30-45-123Z_v035.dex`

### Requirements
- **adb**: Android SDK tools must be installed and in PATH
- **USB Debugging**: Enabled on your Android device
- **Device Connection**: Device connected via USB

## Troubleshooting

If you get "frida: command not found":
1. Install frida globally: `pnpm add -g @frida/tools` or `npm install -g @frida/tools`
2. Or use manual command: `pnpm run build && frida -U -f <app> -l _build/index.js`

## Log Level Configuration

### Available Log Levels
- **ERROR** (0): Only show error messages
- **INFO** (1): Show info, config, hook, and error messages (default)
- **DEBUG** (2): Show debug messages plus all INFO level messages
- **VERBOSE** (3): Show verbose messages plus all DEBUG level messages

### Configuration
Edit the `logLevel` constant in `agent/index.ts`:

```typescript
export const logLevel = Logger.LogLevel.INFO; // Change this value
```

Available options:
- `Logger.LogLevel.ERROR` - Minimal output
- `Logger.LogLevel.INFO` - Default, balanced output
- `Logger.LogLevel.DEBUG` - Show bypass operations
- `Logger.LogLevel.VERBOSE` - Maximum detail

## Manual Testing
After changing the log level:
1. Run `pnpm run build` to compile
2. Observe the different amount of log output based on your setting

## Build Commands
```bash
pnpm run lint    # TypeScript compilation check
pnpm run build   # Compile Frida script
```