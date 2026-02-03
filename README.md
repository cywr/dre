# DRE - Dynamic Reverse Engineering

Frida-based Android reverse engineering toolkit with modular anti-detection bypasses, country-based device profiles, PII monitoring, attribution tracking, cryptographic analysis, and DEX extraction capabilities.

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

| Command                    | Description                               |
| -------------------------- | ----------------------------------------- |
| `pnpm run lint`            | TypeScript compilation check              |
| `pnpm run build`           | Compile Frida script to `_build/index.js` |
| `pnpm run start <package>` | Build and run Frida against target app    |
| `pnpm run pull-dex`        | Pull extracted DEX files from device      |
| `pnpm run format`          | Format codebase with Prettier             |
| `pnpm run proxy`           | Set up transparent proxy via iptables     |
| `pnpm run apps`            | List installed apps on connected device   |

## Quick Start

```bash
# Run against any Android app
pnpm run start com.example.myapp

# Manual execution
pnpm run build
frida -U -f com.example.myapp -l _build/index.js
```

## Configuration

The entry point is `source/index.ts`. Enable or disable modules by commenting/uncommenting lines:

```typescript
setLogLevel(LogLevel.INFO)
setActiveCountry(Country.SINGAPORE)

Java.performNow(() => {
  // Anti-detection (no profile needed)
  AntiRoot.perform()
  AntiDebug.perform()
  AntiEmulation.perform()

  // Device & system spoofing (needs profile)
  DeviceSpoofing.perform()

  // PII access monitoring
  PIIWatcher.perform()

  // Geo & network spoofing + monitoring (needs profile)
  Geolocation.perform()
  NetworkMonitor.perform()

  // DCL.perform()
  // Reflection.perform()

  SharedPreferences.perform([], ["com.google.android.gms", "com.facebook.ads", ...])

  Base64.perform()
  Cipher.perform()
})

Java.perform(() => {
  Attribution.perform()
  SSLPinning.perform()
})
```

## Country Profiles

Profiles provide realistic device identities per region. Set the active profile before hooking:

```typescript
setActiveCountry(Country.SINGAPORE)
```

### Available Countries

| Enum                | Code | Region         |
| ------------------- | ---- | -------------- |
| `SINGAPORE`         | SG   | Southeast Asia |
| `MALAYSIA`          | MY   | Southeast Asia |
| `THAILAND`          | TH   | Southeast Asia |
| `INDONESIA`         | ID   | Southeast Asia |
| `PHILIPPINES`       | PH   | Southeast Asia |
| `VIETNAM`           | VN   | Southeast Asia |
| `BRAZIL`            | BR   | Latin America  |
| `MEXICO`            | MX   | Latin America  |
| `ARGENTINA`         | AR   | Latin America  |
| `COLOMBIA`          | CO   | Latin America  |
| `CHILE`             | CL   | Latin America  |
| `UNITED_STATES`     | US   | North America  |
| `GERMANY`           | DE   | Europe         |
| `FRANCE`            | FR   | Europe         |
| `UNITED_KINGDOM`    | GB   | Europe         |
| `SPAIN`             | ES   | Europe         |
| `ITALY`             | IT   | Europe         |
| `PORTUGAL`          | PT   | Europe         |

### What Profiles Include

Each profile defines: device model, manufacturer, Build fields, telephony (MCC/MNC, carrier), GPS coordinates, display metrics, user agent string, locale, timezone, and DRM identifiers.

### Modules Using Profiles

`DeviceSpoofing`, `Geolocation`, `NetworkMonitor`, and `PIIWatcher` read from the active country profile.

## Modules

### Anti-Detection

#### AntiRoot

Root detection bypass covering `ApplicationPackageManager` (package checks), `File` (root binary checks), `Runtime` (command execution), `ProcessBuilder` (process creation), `SystemProperties` (property spoofing), `String` (string-based detection), and `BufferedReader` (file reading interception). Native `libc.so system()` calls are also intercepted.

#### AntiDebug

Debug detection bypass for `Debug.isDebuggerConnected` and related checks.

#### AntiEmulation

Emulator detection bypass via `SensorManager` (sensor availability), `Activity` (activity monitoring), system properties (`ro.hardware`, `ro.product.model`, etc.), and `UUID`/`MediaDrm` manipulation.

### Spoofing (Profile-Driven)

#### DeviceSpoofing

Spoofs `Build` fields, `MediaDrm` device ID, `Sensor` hardware info, `WebView` user agent, `Settings.Secure` (Android ID), `Settings.Global` (ADB status), and battery-related intents.

#### Geolocation

Spoofs `TelephonyManager` (MCC/MNC, carrier, SIM info), `Location` (GPS coordinates), `LocationManager` (provider info), `Resources`/`ResourcesImpl` (locale configuration), and timezone.

#### NetworkMonitor

Spoofs and monitors `ConnectivityManager` (network state), `NetworkInfo` (connection type), `WifiInfo` (MAC, SSID, BSSID), `InetAddress` (IP resolution), and URL connections.

### Monitoring

#### PIIWatcher

Monitors PII access via `ContentResolver` (with URI classification for contacts, SMS, call log, calendars, etc.), clipboard reads, `AccountManager`, audio recording, and `CookieManager`.

#### Attribution

Tracks attribution SDK activity: AppsFlyer (direct and obfuscated calls), Google Install Referrer API, and WebView URL correlation.

#### SharedPreferences

Monitors all `get*`/`put*`/`contains`/`remove` operations with optional file filtering. Accepts include/exclude file lists.

#### Base64

Intercepts `android.util.Base64` encode/decode operations with data logging and automatic DEX file extraction.

#### Cipher

Intercepts `javax.crypto.Cipher` operations: logs algorithm, operation mode (encrypt/decrypt), encryption keys (hex + ASCII), IV parameters (IvParameterSpec, GCMParameterSpec), doFinal input/output, and automatically extracts DEX files.

#### DCL (Dynamic Class Loading)

Monitors runtime class loading via `DexClassLoader`, `PathClassLoader`, `InMemoryDexClassLoader`, and `BaseDexClassLoader`. Auto-hooks methods of loaded classes.

#### Reflection

Tracks `Method.invoke()` and `Constructor.newInstance()` calls with system class filtering to reduce noise.

### SSL Pinning Bypass

**Java layer:** SSLContext TrustManager replacement, TrustManagerImpl, HostnameVerifier, OkHttp3, legacy OkHttp, WebViewClient, and Trustkit.

**Native layer:** Flutter BoringSSL (export lookup + pattern scan), generic BoringSSL/OpenSSL for Unity, Cocos2d, and Xamarin.

## DEX File Extraction

DEX files are automatically detected and extracted when passing through Base64 or Cipher operations.

### Extraction Workflow

1. **Run the Frida script** to generate DEX files:

```bash
pnpm run start com.example.app
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

| Level     | Value | Shows                                 |
| --------- | ----- | ------------------------------------- |
| `ERROR`   | 0     | Only error messages                   |
| `INFO`    | 1     | Info, config, hook messages (default) |
| `DEBUG`   | 2     | Debug messages + INFO level           |
| `VERBOSE` | 3     | All messages                          |

### Configuration

Edit `source/index.ts`:

```typescript
setLogLevel(LogLevel.INFO) // Change as needed
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
│   ├── index.ts                  # Main entry point
│   ├── scratchpad.ts             # Experimental hooks workspace
│   ├── hooks/
│   │   ├── index.ts              # Hook re-exports
│   │   ├── native/
│   │   │   ├── index.ts
│   │   │   └── libc.ts           # Native libc hooks
│   │   └── tools/
│   │       ├── index.ts          # Tool re-exports
│   │       ├── antidebug.ts
│   │       ├── antiemulation.ts
│   │       ├── antiroot.ts
│   │       ├── attribution.ts
│   │       ├── base64.ts
│   │       ├── cipher.ts
│   │       ├── dcl.ts
│   │       ├── device.ts
│   │       ├── geolocation.ts
│   │       ├── native.ts         # Native helper utilities
│   │       ├── network.ts
│   │       ├── pii.ts
│   │       ├── reflection.ts
│   │       ├── sharedpreferences.ts
│   │       └── sslpinning.ts
│   ├── scripts/
│   │   ├── run.sh                # Build & run script
│   │   ├── pull_dex.sh           # DEX extraction script
│   │   └── proxy.sh              # Transparent proxy setup
│   └── utils/
│       ├── logger.ts             # Logging system
│       ├── dexextractor.ts       # DEX detection/extraction
│       ├── functions.ts          # Utility functions
│       ├── enums/
│       │   ├── index.ts
│       │   ├── android.ts        # Android enum constants
│       │   └── country.ts        # Country profile codes
│       ├── interfaces/
│       │   ├── index.ts
│       │   └── spoofing.ts       # Spoofing interfaces
│       └── types/
│           ├── index.ts
│           ├── constants.ts      # Detection constants
│           ├── profileManager.ts # Profile management
│           └── profiles.ts       # Country profile data
├── _build/                       # Compiled output
└── package.json
```

## Scratchpad

`source/scratchpad.ts` is a workspace for experimental hooks. It runs inside `Java.perform()` and has access to the `Native` helper for quick native function hooking, export/import listing, and memory inspection.

## Transparent Proxy

`source/scripts/proxy.sh` sets up iptables-based traffic redirection through mitmproxy for HTTP/HTTPS interception on a rooted device.

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
