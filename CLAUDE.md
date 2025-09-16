# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build and Run
```bash
pnpm run build          # Compile Frida script using frida-compile
pnpm run lint           # TypeScript compilation check
./run.sh <package-name> # Build and run Frida against target app (RECOMMENDED)
pnpm run start <package-name> # Alternative way to run via pnpm script
```

### Manual Frida Execution
```bash
pnpm run build && frida -U -f <package-name> -l _build/index.js
```

### Specific App Testing
```bash
pnpm run owasp.mstg.uncrackable1  # Test against OWASP UnCrackable Level 1
```

## Architecture Overview

This is a **Frida-based Android hooking framework** for reverse engineering and security testing.

### Core Structure
- **`source/index.ts`**: Main entry point that initializes hooks and configures logging
- **`source/hooks/`**: Main hooks directory organized by category:
  - **`source/hooks/classes/`**: Android/Java class-specific hooks (50+ classes)
  - **`source/hooks/native/`**: Native library hooks (libc, etc.)
  - **`source/hooks/tools/`**: Utility hooks (cipher, base64, reflection, DCL, native tools)
- **`source/utils/logger.ts`**: Centralized logging system with configurable verbosity levels
- **`source/scratchpad.ts`**: Interactive development/testing environment

### Hook System Architecture
The framework uses a modular approach with three main categories:

#### 1. Class Hooks (`source/hooks/classes/`)
Individual hooks for specific Android/Java classes, including:
- **System Properties**: `android.os.SystemProperties`, `android.os.Build`
- **Security**: `javax.net.ssl.SSLContext`, `javax.net.ssl.X509TrustManager`
- **Device Information**: `android.telephony.TelephonyManager`, `android.hardware.SensorManager`
- **File System**: `java.io.File`, `java.io.BufferedReader`
- **Network**: `android.net.ConnectivityManager`, `java.net.InetAddress`
- **And many more** - see `source/hooks/classes/index.ts` for full list

#### 2. Native Hooks (`source/hooks/native/`)
- **libc hooks**: Native library function interception

#### 3. Tool Hooks (`source/hooks/tools/`)
- **Cipher**: Cryptographic operations monitoring
- **Base64**: Base64 encoding/decoding tracking
- **Reflection**: Java reflection call monitoring
- **DCL**: Dynamic Class Loading detection
- **Native**: Native method hooking utilities

### Active Hook Configuration
Hooks are selectively enabled in `source/index.ts`. Currently active:
- Cipher monitoring
- Base64 tracking  
- Dynamic Class Loading detection
- Reflection monitoring
- Scratchpad environment

Disabled hooks (commented out):
- Cloaking (device spoofing)
- General monitoring

### Logging System
Configure logging verbosity in `source/index.ts` by setting `logLevel`:
- `Logger.LogLevel.ERROR` (0): Only errors
- `Logger.LogLevel.INFO` (1): Default level - info, config, hook, and error messages
- `Logger.LogLevel.DEBUG` (2): Debug messages + INFO level
- `Logger.LogLevel.VERBOSE` (3): Maximum detail + all previous levels

### Build System
- Uses `frida-compile` to compile TypeScript to JavaScript
- Output goes to `_build/index.js`
- The `run.sh` script handles intelligent rebuilding (only rebuilds if source is newer)

### Development Patterns
- **Modular Hook Design**: Each hook is isolated and can be enabled/disabled independently
- **Class-Specific Targeting**: Individual classes have dedicated hook files for focused analysis
- **Comprehensive Coverage**: 50+ Android/Java classes are available for hooking
- **Native Integration**: Supports both Java/Android hooks and native library interception

### Prerequisites
Requires global Frida installation:
```bash
pnpm add -g @frida/tools
# or
npm install -g @frida/tools
# or
pip install frida-tools
```