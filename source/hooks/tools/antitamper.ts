import Java from "frida-java-bridge"
import { log, LogType } from "../../utils/logger"

/**
 * Anti-Tamper / Anti-Termination
 * Prevents the app from killing itself when it detects instrumentation.
 */
export namespace AntiTamper {
  const NAME = "[AntiTamper]"

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Anti-Tamper (Self-Termination Block) \x1b[0m` +
        `\n║ ├── Java: System.exit, Runtime.exit` +
        `\n║ ├── Java: Process.killProcess, Process.exitProcess` +
        `\n║ ├── Native: exit(), _exit(), abort() → no-op` +
        `\n║ ├── Native: kill(self, sig) → kill(self, 0)` +
        `\n║ ├── Native: syscall() → neutralize exit/kill syscalls` +
        `\n║ ├── Native: raise(sig) → block fatal signals` +
        `\n║ └── Native: tgkill(self, tid, sig) → block fatal signals` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(): void {
    info()
    try {
      hookSystemExit()
      hookRuntimeExit()
      hookProcessKill()
      // hookProcessExit() — removed: accessing Process.exitProcess on pre-API 34
      // devices crashes the Frida Java bridge at native level
    } catch (error) {
      log(LogType.Error, NAME, `Hooks failed: ${error}`)
    }
  }

  // ─── System.exit() ────────────────────────────────────────────────────

  function hookSystemExit(): void {
    try {
      const System = Java.use("java.lang.System")

      System.exit.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          log(LogType.Info, NAME, `System.exit(${args[0]}) blocked`)
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `System.exit hook failed: ${error}`)
    }
  }

  // ─── Runtime.exit() ───────────────────────────────────────────────────

  function hookRuntimeExit(): void {
    try {
      const Runtime = Java.use("java.lang.Runtime")

      Runtime.exit.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          log(LogType.Info, NAME, `Runtime.exit(${args[0]}) blocked`)
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `Runtime.exit hook failed: ${error}`)
    }
  }

  // ─── Process.killProcess() ────────────────────────────────────────────

  function hookProcessKill(): void {
    try {
      const Process = Java.use("android.os.Process")

      Process.killProcess.implementation = function (pid: number) {
        const myPid = Process.myPid()

        if (pid === myPid) {
          log(LogType.Info, NAME, `Process.killProcess(${pid}) blocked (own PID)`)
          return
        }

        log(LogType.Debug, NAME, `Process.killProcess(${pid}) allowed (not own PID ${myPid})`)
        return this.killProcess(pid)
      }
    } catch (error) {
      log(LogType.Error, NAME, `Process.killProcess hook failed: ${error}`)
    }
  }

  // ─── Process.exitProcess() (API 34+) ─────────────────────────────────

  function hookProcessExit(): void {
    try {
      const Process = Java.use("android.os.Process")

      if (Process.exitProcess) {
        Process.exitProcess.implementation = function (code: number) {
          log(LogType.Info, NAME, `Process.exitProcess(${code}) blocked`)
          // No-op: prevent termination
        }
      }
    } catch (error) {
      // Expected on API < 34 where exitProcess doesn't exist
      log(LogType.Debug, NAME, `Process.exitProcess not available (pre-API 34): ${error}`)
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  //  Native hooks — block libc termination functions
  // ═══════════════════════════════════════════════════════════════════

  const GUARD_KEY = "__dre_antitamper_native__"

  const SYSCALL_NUMBERS: Record<
    string,
    {
      exit: number
      exit_group: number
      kill: number
      tgkill: number
      tkill: number
      getpid: number
    }
  > = {
    arm64: { exit: 93, exit_group: 94, kill: 129, tgkill: 131, tkill: 130, getpid: 172 },
    arm: { exit: 1, exit_group: 248, kill: 37, tgkill: 270, tkill: 238, getpid: 20 },
    x64: { exit: 60, exit_group: 231, kill: 62, tgkill: 234, tkill: 200, getpid: 39 },
    ia32: { exit: 1, exit_group: 252, kill: 37, tgkill: 270, tkill: 238, getpid: 20 },
  }

  // Signals commonly used by anti-tamper to kill the process.
  // EXCLUDES SIGSEGV(11), SIGBUS(7), SIGTRAP(5) — ART uses these
  // for implicit null checks and debugging. Intercepting them breaks
  // the runtime (ANR, hangs).
  const FATAL_SIGNALS = new Set([1, 2, 3, 6, 9, 14, 15]) // SIGHUP, SIGINT, SIGQUIT, SIGABRT, SIGKILL, SIGALRM, SIGTERM

  /**
   * Install native-level hooks for libc termination functions.
   * Can be called outside Java.perform — no VM dependency.
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

      hookNativeExit(libc)
      hookNativeExitUnderscore(libc)
      hookNativeAbort(libc)
      hookNativeKill(libc)
      hookNativeSyscall(libc)
      hookNativeRaise(libc)
      hookNativeTgkill(libc)
      log(LogType.Info, NAME, "Native hooks installed")
    } catch (error) {
      log(LogType.Error, NAME, `Native hooks failed: ${error}`)
    }
  }

  // ─── exit() ─────────────────────────────────────────────────────

  function hookNativeExit(libc: Module): void {
    const exitPtr = libc.findExportByName("exit")
    if (!exitPtr) {
      log(LogType.Error, NAME, "exit not found in libc.so")
      return
    }

    // exit() is noreturn — redirect PC to the return address in onEnter,
    // effectively making exit() a no-op that "returns" to the caller.
    // This avoids blocking the thread (which would prevent ActivityManager
    // attachment and trigger a 10s SIGKILL timeout).
    Interceptor.attach(exitPtr, {
      onEnter(args) {
        log(LogType.Info, NAME, `exit(${args[0].toInt32()}) blocked`)
        this.context.pc = this.returnAddress
      },
    })
  }

  // ─── _exit() ────────────────────────────────────────────────────

  function hookNativeExitUnderscore(libc: Module): void {
    const exitPtr = libc.findExportByName("_exit")
    if (!exitPtr) {
      log(LogType.Error, NAME, "_exit not found in libc.so")
      return
    }

    Interceptor.attach(exitPtr, {
      onEnter(args) {
        log(LogType.Info, NAME, `_exit(${args[0].toInt32()}) blocked`)
        this.context.pc = this.returnAddress
      },
    })
  }

  // ─── abort() ────────────────────────────────────────────────────

  function hookNativeAbort(libc: Module): void {
    const abortPtr = libc.findExportByName("abort")
    if (!abortPtr) {
      log(LogType.Error, NAME, "abort not found in libc.so")
      return
    }

    Interceptor.attach(abortPtr, {
      onEnter() {
        log(LogType.Info, NAME, `abort() blocked`)
        this.context.pc = this.returnAddress
      },
    })
  }

  // ─── kill() ─────────────────────────────────────────────────────

  function hookNativeKill(libc: Module): void {
    const killPtr = libc.findExportByName("kill")
    if (!killPtr) {
      log(LogType.Error, NAME, "kill not found in libc.so")
      return
    }

    const getpidPtr = libc.findExportByName("getpid")
    if (!getpidPtr) {
      log(LogType.Error, NAME, "getpid not found in libc.so")
      return
    }

    const getpid = new NativeFunction(getpidPtr, "int", [])

    Interceptor.attach(killPtr, {
      onEnter(args) {
        const pid = args[0].toInt32()
        const sig = args[1].toInt32()
        const myPid = getpid() as number

        if (pid === myPid) {
          log(LogType.Info, NAME, `kill(${pid}, ${sig}) → kill(${pid}, 0) [self-kill neutralized]`)
          // Change signal to 0 (harmless "does process exist?" check)
          args[1] = ptr(0)
        }
      },
    })
  }

  // ─── syscall() ──────────────────────────────────────────────────────

  function hookNativeSyscall(libc: Module): void {
    const syscallPtr = libc.findExportByName("syscall")
    if (!syscallPtr) {
      log(LogType.Error, NAME, "syscall not found in libc.so")
      return
    }

    const table = SYSCALL_NUMBERS[Process.arch]
    if (!table) {
      log(LogType.Error, NAME, `No syscall numbers for arch: ${Process.arch}`)
      return
    }

    const getpidPtr = libc.findExportByName("getpid")
    if (!getpidPtr) {
      log(LogType.Error, NAME, "getpid not found in libc.so")
      return
    }
    const getpid = new NativeFunction(getpidPtr, "int", [])

    Interceptor.attach(syscallPtr, {
      onEnter(args) {
        const nr = args[0].toInt32()

        if (nr === table.exit || nr === table.exit_group) {
          log(
            LogType.Info,
            NAME,
            `syscall(${nr}) [exit/exit_group] → syscall(${table.getpid}) [getpid]`,
          )
          args[0] = ptr(table.getpid)
        } else if (nr === table.kill) {
          const pid = args[1].toInt32()
          const sig = args[2].toInt32()
          const myPid = getpid() as number
          if (pid === myPid && FATAL_SIGNALS.has(sig)) {
            log(LogType.Info, NAME, `syscall(kill, ${pid}, ${sig}) → sig=0 [self-kill neutralized]`)
            args[2] = ptr(0)
          }
        } else if (nr === table.tgkill) {
          const tgid = args[1].toInt32()
          const sig = args[3].toInt32()
          const myPid = getpid() as number
          if (tgid === myPid && FATAL_SIGNALS.has(sig)) {
            log(LogType.Info, NAME, `syscall(tgkill, ${tgid}, tid, ${sig}) → sig=0 [neutralized]`)
            args[3] = ptr(0)
          }
        } else if (nr === table.tkill) {
          const sig = args[2].toInt32()
          if (FATAL_SIGNALS.has(sig)) {
            log(LogType.Info, NAME, `syscall(tkill, tid, ${sig}) → sig=0 [neutralized]`)
            args[2] = ptr(0)
          }
        }
      },
    })
  }

  // ─── raise() ──────────────────────────────────────────────────────

  function hookNativeRaise(libc: Module): void {
    const raisePtr = libc.findExportByName("raise")
    if (!raisePtr) {
      log(LogType.Error, NAME, "raise not found in libc.so")
      return
    }

    Interceptor.attach(raisePtr, {
      onEnter(args) {
        const sig = args[0].toInt32()
        if (FATAL_SIGNALS.has(sig)) {
          log(LogType.Info, NAME, `raise(${sig}) → raise(0) [fatal signal blocked]`)
          args[0] = ptr(0)
        }
      },
    })
  }

  // ─── tgkill() ─────────────────────────────────────────────────────

  function hookNativeTgkill(libc: Module): void {
    const tgkillPtr = libc.findExportByName("tgkill")
    if (!tgkillPtr) {
      log(LogType.Error, NAME, "tgkill not found in libc.so")
      return
    }

    const getpidPtr = libc.findExportByName("getpid")
    if (!getpidPtr) {
      log(LogType.Error, NAME, "getpid not found in libc.so")
      return
    }
    const getpid = new NativeFunction(getpidPtr, "int", [])

    Interceptor.attach(tgkillPtr, {
      onEnter(args) {
        const tgid = args[0].toInt32()
        const sig = args[2].toInt32()
        const myPid = getpid() as number

        if (tgid === myPid && FATAL_SIGNALS.has(sig)) {
          log(LogType.Info, NAME, `tgkill(${tgid}, tid, ${sig}) → sig=0 [fatal signal blocked]`)
          args[2] = ptr(0)
        }
      },
    })
  }
}
