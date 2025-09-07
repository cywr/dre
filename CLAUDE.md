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

This is a **Frida-based anti-emulation bypass framework** for Android reverse engineering and security testing.

### Core Structure
- **`agent/index.ts`**: Main entry point that initializes hooks and configures logging
- **`agent/interfaces/hook.ts`**: Abstract Hook class that all bypass modules extend
- **`agent/scripts/system/`**: Individual bypass modules for different Android security mechanisms
- **`agent/utils/logger.ts`**: Centralized logging system with configurable verbosity levels
- **`agent/scripts/modules.ts`**: Module exports aggregator

### Hook System
All bypass functionality is implemented as Hook classes extending the abstract Hook base class. Each hook must implement:
- `NAME`: String identifier for the hook
- `LOG_TYPE`: Logger type for consistent output formatting
- `info()`: Hook information/description
- `execute()`: Main hook implementation

### Available Bypass Modules
- **Rooting**: Bypass root detection mechanisms
- **Debug**: Disable anti-debugging protections  
- **Spoofing**: Comprehensive device/system spoofing (merged from DeviceCloaking)
- **SSLPinning**: Bypass SSL certificate pinning
- **Cipher**: Hook cryptographic operations
- **Base64**: Monitor Base64 encoding/decoding
- **SharedPreferencesWatcher**: Monitor Android SharedPreferences access

### Logging System
Configure logging verbosity in `agent/index.ts` by setting `logLevel`:
- `Logger.LogLevel.ERROR` (0): Only errors
- `Logger.LogLevel.INFO` (1): Default level - info, config, hook, and error messages
- `Logger.LogLevel.DEBUG` (2): Debug messages + INFO level
- `Logger.LogLevel.VERBOSE` (3): Maximum detail + all previous levels

### Build System
- Uses `frida-compile` to compile TypeScript to JavaScript
- Output goes to `_build/index.js`
- The `run.sh` script handles intelligent rebuilding (only rebuilds if source is newer)

### Hook Implementation Patterns
- **Overload Consolidation**: All hooks use `.overloads.forEach()` pattern for cleaner code
- **Unified Logging**: Consistent logging format across all hook modules
- **Error Handling**: Individual hook methods wrapped in try-catch blocks
- **Modular Design**: Each security bypass is isolated in its own class extending Hook

### Prerequisites
Requires global Frida installation:
```bash
pnpm add -g @frida/tools
# or
npm install -g @frida/tools
# or
pip install frida-tools
```