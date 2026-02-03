import Java from "frida-java-bridge"
import { log, LogType } from "../../utils/logger"

/**
 * Anti-Debug Detection Bypass
 * Bypasses debugger detection checks.
 */
export namespace AntiDebug {
  const NAME = "[AntiDebug]"

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Anti-Debug Detection Bypass \x1b[0m` +
        `\n║ └── Debug: isDebuggerConnected, waitingForDebugger` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(): void {
    info()
    try {
      hookDebug()
    } catch (error) {
      log(LogType.Error, NAME, `Hooks failed: \n${error}`)
    }
  }

  function hookDebug(): void {
    try {
      const DebugClass = Java.use("android.os.Debug")

      DebugClass.isDebuggerConnected.implementation = function () {
        log(LogType.Info, NAME, "Debug.isDebuggerConnected: false")
        return false
      }
    } catch (error) {
      log(LogType.Error, NAME, `Debug hook failed: ${error}`)
    }
  }
}
