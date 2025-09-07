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