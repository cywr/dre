import Java from "frida-java-bridge"
import { log, LogType } from "../../utils/logger"

/**
 * Anti-Frida Detection Bypass
 * Hides Frida instrumentation from target apps via native and Java-level hooks.
 */
export namespace AntiFrida {
  const NAME = "[AntiFrida]"

  // Tracked FILE* pointers opened on /proc/self/maps, status, or task/<tid>/comm
  const trackedFiles = new Set<string>()

  /** Frida-related strings to filter from /proc reads */
  const FRIDA_STRINGS = ["frida", "gadget", "linjector", "gum-js-loop", "gmain", "gdbus"]

  /** Frida-specific file paths to hide */
  const FRIDA_PATHS = [
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida-agent",
    "/data/local/tmp/frida-gadget",
  ]

  /** Frida's default listening port */
  const FRIDA_PORT = 27042

  /** Regex to match /proc/self/task/<tid>/comm */
  const PROC_TASK_COMM = new RegExp("^/proc/self/task/\\d+/comm$")

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Anti-Frida Detection Bypass \x1b[0m` +
        `\n║ ├── Native: fopen, fgets, connect` +
        `\n║ └── Java: File.exists` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  /**
   * Install Java-level hooks (must be called inside Java.perform/performNow)
   */
  export function perform(): void {
    info()
    try {
      hookFileExists()
    } catch (error) {
      log(LogType.Error, NAME, `Java hooks failed: ${error}`)
    }
  }

  const GUARD_KEY = "__dre_antifrida_native__"

  /**
   * Install native-level hooks (can be called outside Java.perform)
   */
  export function performNative(): void {
    if ((globalThis as any)[GUARD_KEY]) return
    ;(globalThis as any)[GUARD_KEY] = true

    try {
      const libc = Process.findModuleByName("libc.so")
      if (!libc) {
        log(LogType.Error, NAME, "libc.so not found")
        return
      }

      hookFopen(libc)
      hookFgets(libc)
      hookConnect(libc) // TEST: disabled to isolate crash
      log(LogType.Info, NAME, "Native hooks installed")
    } catch (error) {
      log(LogType.Error, NAME, `Native hooks failed: ${error}`)
    }
  }

  // ─── fopen() ─────────────────────────────────────────────────────────

  function hookFopen(libc: Module): void {
    const fopenPtr = libc.findExportByName("fopen")
    if (!fopenPtr) {
      log(LogType.Error, NAME, "fopen not found in libc.so")
      return
    }

    Interceptor.attach(fopenPtr, {
      onEnter(args) {
        this.shouldTrack = false
        try {
          const pathname = args[0].readUtf8String()
          if (pathname) {
            if (
              pathname === "/proc/self/maps" ||
              pathname === "/proc/self/status" ||
              PROC_TASK_COMM.test(pathname)
            ) {
              this.shouldTrack = true
            }
          }
        } catch (_) {
          // Ignore read errors
        }
      },
      onLeave(retval) {
        if (this.shouldTrack && !retval.isNull()) {
          trackedFiles.add(retval.toString())
        }
      },
    })
  }

  // ─── fgets() ────────────────────────────────────────────────────────

  function hookFgets(libc: Module): void {
    const fgetsPtr = libc.findExportByName("fgets")
    if (!fgetsPtr) {
      log(LogType.Error, NAME, "fgets not found in libc.so")
      return
    }

    Interceptor.attach(fgetsPtr, {
      onEnter(args) {
        this.buf = args[0]
        this.stream = args[2]
      },
      onLeave(retval) {
        if (retval.isNull() || !trackedFiles.has(this.stream.toString())) {
          return
        }

        try {
          const line = this.buf.readUtf8String()
          if (!line) return

          const lower = line.toLowerCase()
          if (FRIDA_STRINGS.some((s) => lower.includes(s))) {
            this.buf.writeUtf8String("\n")
          }
        } catch (_) {
          // Not valid UTF-8, ignore
        }
      },
    })
  }

  // ─── connect() ────────────────────────────────────────────────────────

  function hookConnect(libc: Module): void {
    const connectPtr = libc.findExportByName("connect")
    if (!connectPtr) {
      log(LogType.Error, NAME, "connect not found in libc.so")
      return
    }

    const errnoPtr = libc.findExportByName("__errno")
    const errnoFunc = errnoPtr ? new NativeFunction(errnoPtr, "pointer", []) : null

    Interceptor.attach(connectPtr, {
      onEnter(args) {
        this.block = false
        try {
          const sockaddr = args[1]
          const family = sockaddr.readU16()

          // AF_INET = 2
          if (family === 2) {
            const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8()
            const ip =
              sockaddr.add(4).readU8() +
              "." +
              sockaddr.add(5).readU8() +
              "." +
              sockaddr.add(6).readU8() +
              "." +
              sockaddr.add(7).readU8()

            if (ip === "127.0.0.1" && port === FRIDA_PORT) {
              log(LogType.Info, NAME, `Blocking connect to ${ip}:${port}`)
              this.block = true
            }
          }
        } catch (_) {
          // Ignore read errors
        }
      },
      onLeave(retval) {
        if (this.block) {
          // Set errno to ECONNREFUSED (111)
          if (errnoFunc) {
            const errnoLocation = errnoFunc() as NativePointer
            errnoLocation.writeS32(111)
          }
          retval.replace(ptr(-1))
        }
      },
    })
  }

  // ─── File.exists() ────────────────────────────────────────────────────

  function hookFileExists(): void {
    try {
      const File = Java.use("java.io.File")

      File.exists.implementation = function () {
        const path = this.getAbsolutePath()

        if (FRIDA_PATHS.some((fp) => path === fp)) {
          log(LogType.Info, NAME, `File.exists: hiding ${path}`)
          return false
        }

        return this.exists.call(this)
      }
    } catch (error) {
      log(LogType.Error, NAME, `File.exists hook failed: ${error}`)
    }
  }
}
