# DRE - Dynamic Reverse Engineering

Frida-based Android reverse engineering toolkit with comprehensive anti-detection bypasses, cryptographic monitoring, and DEX extraction capabilities.

## Prerequisites

- **Node.js** and **pnpm/npm**
- **Frida** installed globally:
```bash
pnpm add -g @frida/tools
# or
npm install -g @frida/tools
# or
pip install frida-tools
```
- **Android device** with USB debugging enabled and Frida server running
- **adb** (Android SDK) for DEX file extraction

## Package Scripts

| Command | Description |
|---------|-------------|
| `pnpm run lint` | TypeScript compilation check |
| `pnpm run build` | Compile Frida script to `_build/index.js` |
| `pnpm run start <package>` | Build and run Frida against target app |
| `pnpm run pull-dex` | Pull extracted DEX files from device |

## Quick Start

```bash
# Run against any Android app
./run.sh com.example.myapp

# Or using pnpm/npm
pnpm run start com.example.myapp

# Manual execution
pnpm run build
frida -U -f com.example.myapp -l _build/index.js
```

## Features

### Cloaking Module (Anti-Detection Suite)

The main cloaking module (`Hooks.Cloaking.perform()`) provides comprehensive bypasses:

#### Anti-Rooting
- `ApplicationPackageManager` - Package installation checks
- `File` - Root binary file existence checks
- `Runtime` - Command execution monitoring
- `ProcessBuilder` - Process creation hooks
- `SystemProperties` - System property spoofing
- `String` - String-based root detection
- `BufferedReader` - File reading interception

#### Anti-Debug
- `Debug` - Debug detection bypass (isDebuggerConnected, etc.)

#### Anti-Emulation
- `SensorManager` - Sensor availability spoofing
- `Activity` - Activity monitoring
- `System` - System property manipulation
- `UUID` - DRM UUID manipulation

#### Device Spoofing
- `Build` - Device build information
- `TelephonyManager` - IMEI, phone number, etc.
- `MediaDrm` - DRM device ID
- `Sensor` - Hardware sensor information
- `ContextImpl` - Context-based device info

#### Network Spoofing
- `ConnectivityManager` - Network state
- `NetworkInfo` - Network information
- `WifiInfo` - WiFi details (MAC, SSID, etc.)
- `InetAddress` - IP address resolution
- `WebView` - WebView user agent

#### Location Spoofing
- `LocationManager` - GPS provider information
- `Location` - GPS coordinates

#### System Spoofing
- `Settings.Secure` - Secure settings (Android ID, etc.)
- `Settings.Global` - Global settings (ADB enabled, etc.)
- `ContentResolver` - Content provider queries
- `Intent` - Intent interception
- `Resources` / `ResourcesImpl` - Resource access

### Analysis Tools

Enable these in `source/index.ts` by uncommenting:

```typescript
Java.performNow(() => {
    Hooks.Cloaking.perform()      // Anti-detection suite
    // Hooks.DCL.perform()         // Dynamic class loading
    // Hooks.Reflection.perform()  // Reflection monitoring
    // Hooks.SSLPinning.perform()  // SSL pinning bypass
    // Hooks.SharedPreferences.perform()  // SharedPrefs monitoring

    Hooks.Base64.perform()        // Base64 operations + DEX extraction
    Hooks.Cipher.perform()        // Crypto operations + DEX extraction
});
```

#### Base64 Monitor
Intercepts `android.util.Base64` encode/decode operations:
- Logs input/output data
- Automatically extracts DEX files

#### Cipher Monitor
Intercepts `javax.crypto.Cipher` operations:
- Logs algorithm, operation mode (encrypt/decrypt)
- Dumps encryption keys (hex + ASCII)
- Dumps IV parameters (IvParameterSpec, GCMParameterSpec)
- Logs doFinal input/output
- Automatically extracts DEX files

#### Dynamic Class Loading (DCL)
Monitors runtime class loading:
- `DexClassLoader`
- `PathClassLoader`
- `InMemoryDexClassLoader`
- `BaseDexClassLoader`
- Auto-hooks methods of loaded classes

#### Reflection Monitor
Tracks reflective API usage:
- `Method.invoke()` calls
- `Constructor.newInstance()` calls
- Filters system classes to reduce noise

#### SharedPreferences Monitor
Monitors read/write operations:
- All `get*` methods (getString, getInt, getBoolean, etc.)
- All `put*` methods
- `contains` and `remove` operations
- Optional filtering by target file

#### SSL Pinning Bypass
Comprehensive certificate validation bypass:
- SSLContext TrustManager replacement
- X509TrustManager bypass
- Android TrustManagerImpl bypass

## DEX File Extraction

DEX files are automatically detected and extracted when passing through Base64 or Cipher operations.

### Extraction Workflow

1. **Run the Frida script** to generate DEX files:
```bash
./run.sh com.example.app
```

2. **Pull DEX files** from device:
```bash
pnpm run pull-dex
```

### File Naming
Files are saved as: `dex_{context}_{operation}_{timestamp}_v{version}.dex`

Example: `dex_Base64_decode_2024-09-16T10-30-45-123Z_v035.dex`

### Device Paths Checked
- `/sdcard/Download/dre_extractions`
- `/sdcard/Documents/dre_extractions`
- `/data/local/tmp/dre_extractions`
- `/sdcard/dre_extractions`

### Local Output
Files are pulled to: `_build/dex_extractions/`

## Log Level Configuration

### Available Levels
| Level | Value | Shows |
|-------|-------|-------|
| `ERROR` | 0 | Only error messages |
| `INFO` | 1 | Info, config, hook messages (default) |
| `DEBUG` | 2 | Debug messages + INFO level |
| `VERBOSE` | 3 | All messages |

### Configuration
Edit `source/index.ts`:

```typescript
Logger.setLogLevel(Logger.LogLevel.INFO);  // Change as needed
```

### Log Types
- `[i]` (Cyan) - Info
- `[*]` (Blue) - Config
- `[+]` (Green) - Hook
- `[?]` (Yellow) - Debug
- `[v]` (Magenta) - Verbose
- `[!]` (Red) - Error

## Project Structure

```
dre/
├── source/
│   ├── index.ts              # Main entry point
│   ├── scratchpad.ts         # Custom hooks workspace
│   ├── hooks/
│   │   ├── cloaking.ts       # Anti-detection orchestrator
│   │   ├── classes/          # Individual class hooks
│   │   ├── tools/            # Analysis tools (Base64, Cipher, etc.)
│   │   └── native/           # Native code hooks
│   └── utils/
│       ├── logger.ts         # Logging system
│       ├── dexextractor.ts   # DEX detection/extraction
│       └── functions.ts      # Utility functions
├── _build/                   # Compiled output
├── run.sh                    # Build & run script
└── pull_dex.sh              # DEX extraction script
```

## Troubleshooting

### Frida not found
```bash
# Install globally
pnpm add -g @frida/tools
# or
npm install -g @frida/tools
# or
pip install frida-tools
```

### No device connected
```bash
# Check device connection
adb devices

# Ensure USB debugging is enabled on device
# Start Frida server on device
adb shell "/data/local/tmp/frida-server &"
```

### Build errors
```bash
# Check TypeScript compilation
pnpm run lint

# Rebuild
pnpm run build
```
