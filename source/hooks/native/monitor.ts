import { log, logOnce, LogType } from "../../utils/logger"
import {
  DLSYM_IGNORE_LIST,
  JNI_IGNORE_LIST,
  LINKER_IGNORE_LIST,
  SYSCALL_FILE_IGNORE_LIST,
} from "../../utils/types/constants"

/**
 * Unified native monitoring hook. Takes a target library name and reveals
 * everything it does — JNI bridge calls, dynamic loading, file/network I/O,
 * system property queries. Designed for opaque native malware analysis.
 *
 * Usage: NativeMonitor.perform("libtarget.so")
 */
export namespace NativeMonitor {
  const NAME = "[NativeMonitor]"

  function isFromTarget(ctx: InvocationContext, targetModule: Module): boolean {
    const caller = Process.findModuleByAddress(ctx.returnAddress)
    return caller !== null && caller.name === targetModule.name
  }

  function tryReadCString(ptr: NativePointer): string | null {
    if (ptr.isNull()) return null
    try {
      return ptr.readCString()
    } catch {
      return null
    }
  }

  function tryReadBuffer(ptr: NativePointer, len: number): string | null {
    if (ptr.isNull() || len <= 0) return null
    try {
      const size = Math.min(len, 512)
      const buf = ptr.readByteArray(size)
      if (!buf) return null
      // Try as string first, fall back to hex
      try {
        const str = ptr.readCString()
        if (str && str.length > 0 && /^[\x20-\x7e\t\n\r]+$/.test(str.substring(0, 64))) {
          return str.substring(0, 256)
        }
      } catch {
        // not a printable string
      }
      return hexdump(ptr, { length: size, ansi: false })
    } catch {
      return null
    }
  }

  // ── JNI Hooks ──────────────────────────────────────────────────────────

  function hookJNI(): void {
    let libart: Module
    try {
      libart = Process.getModuleByName("libart.so")
    } catch {
      log(LogType.Error, NAME, "libart.so not found — skipping JNI hooks")
      return
    }

    const exports = libart.enumerateExports()
    let hookCount = 0

    for (const exp of exports) {
      if (exp.type !== "function" || !exp.address) continue
      const n = exp.name

      // FindClass
      if (n.includes("FindClass") && !n.includes("CheckJNI")) {
        Interceptor.attach(exp.address, {
          onEnter(args) {
            const cls = tryReadCString(args[1])
            if (!cls) return
            // Filter non-class strings (method names like "init", "create")
            if (!cls.includes("/") && !cls.startsWith("L")) return
            // Normalize JNI descriptors: Lcom/foo/Bar; -> com/foo/Bar
            const normalized = cls.replace(/^L/, "").replace(/;$/, "")
            if (JNI_IGNORE_LIST.some((prefix) => normalized.startsWith(prefix))) return
            logOnce(LogType.Hook, NAME, `JNI FindClass: ${cls}`, `jni-fc:${cls}`)
          },
        })
        hookCount++
        continue
      }

      // GetMethodID / GetStaticMethodID
      if (
        (n.includes("GetMethodID") || n.includes("GetStaticMethodID")) &&
        !n.includes("CheckJNI")
      ) {
        const isStatic = n.includes("Static")
        Interceptor.attach(exp.address, {
          onEnter(args) {
            const method = tryReadCString(args[2])
            const sig = tryReadCString(args[3])
            if (!method) return
            const label = isStatic ? "GetStaticMethodID" : "GetMethodID"
            logOnce(
              LogType.Hook,
              NAME,
              `JNI ${label}: ${method}${sig || ""}`,
              `jni-mid:${label}:${method}:${sig}`,
            )
          },
        })
        hookCount++
        continue
      }

      // GetFieldID / GetStaticFieldID
      if (
        (n.includes("GetFieldID") || n.includes("GetStaticFieldID")) &&
        !n.includes("CheckJNI") &&
        !n.includes("MethodID")
      ) {
        const isStatic = n.includes("Static")
        Interceptor.attach(exp.address, {
          onEnter(args) {
            const field = tryReadCString(args[2])
            const sig = tryReadCString(args[3])
            if (!field) return
            const label = isStatic ? "GetStaticFieldID" : "GetFieldID"
            logOnce(
              LogType.Hook,
              NAME,
              `JNI ${label}: ${field} (${sig || "?"})`,
              `jni-fid:${label}:${field}:${sig}`,
            )
          },
        })
        hookCount++
        continue
      }

      // NewStringUTF
      if (n.includes("NewStringUTF") && !n.includes("CheckJNI")) {
        Interceptor.attach(exp.address, {
          onEnter(args) {
            const str = tryReadCString(args[1])
            if (str) {
              log(LogType.Hook, NAME, `JNI NewStringUTF: "${str}"`)
            }
          },
        })
        hookCount++
        continue
      }

      // GetStringUTFChars
      if (n.includes("GetStringUTFChars") && !n.includes("CheckJNI") && !n.includes("Region")) {
        Interceptor.attach(exp.address, {
          onLeave(retval) {
            const str = tryReadCString(retval)
            if (str) {
              log(LogType.Hook, NAME, `JNI GetStringUTFChars: "${str}"`)
            }
          },
        })
        hookCount++
        continue
      }

      // RegisterNatives — highest-value hook
      if (n.includes("RegisterNatives") && !n.includes("CheckJNI") && !n.includes("Unregister")) {
        Interceptor.attach(exp.address, {
          onEnter(args) {
            const methodsPtr = args[2]
            const count = args[3].toInt32()
            const ptrSize = Process.pointerSize

            log(LogType.Info, NAME, `JNI RegisterNatives: ${count} method(s)`)

            for (let i = 0; i < count; i++) {
              const base = methodsPtr.add(i * 3 * ptrSize)
              const methodName = tryReadCString(base.readPointer())
              const methodSig = tryReadCString(base.add(ptrSize).readPointer())
              const fnPtr = base.add(2 * ptrSize).readPointer()

              const mod = Process.findModuleByAddress(fnPtr)
              const location = mod
                ? `${mod.name}+0x${fnPtr.sub(mod.base).toString(16)}`
                : `0x${fnPtr.toString(16)}`

              log(
                LogType.Info,
                NAME,
                `  native: ${methodName || "?"}${methodSig || ""} -> ${location}`,
              )
            }
          },
        })
        hookCount++
        continue
      }
    }

    log(LogType.Info, NAME, `JNI hooks attached: ${hookCount} functions on libart.so`)
  }

  // ── Linker Hooks ───────────────────────────────────────────────────────

  function hookLinker(): void {
    // Try libdl.so first, fall back to linker64/linker
    let linkerModule: Module | null = null
    for (const name of ["libdl.so", "linker64", "linker"]) {
      try {
        linkerModule = Process.getModuleByName(name)
        break
      } catch {
        continue
      }
    }

    if (!linkerModule) {
      log(LogType.Error, NAME, "No linker module found — skipping linker hooks")
      return
    }

    let hookCount = 0

    // dlopen
    const dlopenAddr = linkerModule.findExportByName("dlopen")
    if (dlopenAddr) {
      Interceptor.attach(dlopenAddr, {
        onEnter(args) {
          const lib = tryReadCString(args[0])
          if (!lib) return
          if (LINKER_IGNORE_LIST.some((ignored) => lib.includes(ignored))) return
          log(LogType.Hook, NAME, `dlopen: ${lib}`)
        },
      })
      hookCount++
    }

    // android_dlopen_ext
    const dlopenExtAddr = linkerModule.findExportByName("android_dlopen_ext")
    if (dlopenExtAddr) {
      Interceptor.attach(dlopenExtAddr, {
        onEnter(args) {
          const lib = tryReadCString(args[0])
          if (!lib) return
          if (LINKER_IGNORE_LIST.some((ignored) => lib.includes(ignored))) return
          log(LogType.Hook, NAME, `android_dlopen_ext: ${lib}`)
        },
      })
      hookCount++
    }

    // dlsym
    const dlsymAddr = linkerModule.findExportByName("dlsym")
    if (dlsymAddr) {
      Interceptor.attach(dlsymAddr, {
        onEnter(args) {
          const sym = tryReadCString(args[1])
          if (!sym) return
          if (DLSYM_IGNORE_LIST.some((prefix) => sym.startsWith(prefix))) return
          log(LogType.Hook, NAME, `dlsym: ${sym}`)
        },
      })
      hookCount++
    }

    log(LogType.Info, NAME, `Linker hooks attached: ${hookCount} functions on ${linkerModule.name}`)
  }

  // ── Syscall Hooks (caller-filtered) ────────────────────────────────────

  function hookSyscalls(targetModule: Module): void {
    let libc: Module
    try {
      libc = Process.getModuleByName("libc.so")
    } catch {
      log(LogType.Error, NAME, "libc.so not found — skipping syscall hooks")
      return
    }

    let hookCount = 0

    // open — file I/O
    const openAddr = libc.findExportByName("open")
    if (openAddr) {
      Interceptor.attach(openAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const path = tryReadCString(args[0])
          if (!path) return
          if (SYSCALL_FILE_IGNORE_LIST.some((ignored) => path.startsWith(ignored))) return
          log(LogType.Hook, NAME, `open: ${path}`)
        },
      })
      hookCount++
    }

    // snprintf — string building
    const snprintfAddr = libc.findExportByName("snprintf")
    if (snprintfAddr) {
      Interceptor.attach(snprintfAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const fmt = tryReadCString(args[2])
          if (fmt) {
            ;(this as any)._buf = args[0]
            ;(this as any)._fmt = fmt
          }
        },
        onLeave(retval) {
          if (!(this as any)._fmt) return
          const result = tryReadCString((this as any)._buf)
          if (result) {
            log(LogType.Hook, NAME, `snprintf: "${result}"`)
          }
        },
      })
      hookCount++
    }

    // strstr — string search
    const strstrAddr = libc.findExportByName("strstr")
    if (strstrAddr) {
      Interceptor.attach(strstrAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const haystack = tryReadCString(args[0])
          const needle = tryReadCString(args[1])
          if (needle) {
            log(
              LogType.Hook,
              NAME,
              `strstr: needle="${needle}"${haystack ? ` in "${haystack.substring(0, 128)}"` : ""}`,
            )
          }
        },
      })
      hookCount++
    }

    // socket — network
    const socketAddr = libc.findExportByName("socket")
    if (socketAddr) {
      Interceptor.attach(socketAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const domain = args[0].toInt32()
          const type = args[1].toInt32()
          // AF_INET=2, AF_INET6=10, SOCK_STREAM=1, SOCK_DGRAM=2
          const domainStr =
            domain === 2 ? "AF_INET" : domain === 10 ? "AF_INET6" : `domain=${domain}`
          const typeStr = type === 1 ? "SOCK_STREAM" : type === 2 ? "SOCK_DGRAM" : `type=${type}`
          log(LogType.Hook, NAME, `socket: ${domainStr}, ${typeStr}`)
        },
      })
      hookCount++
    }

    // sendto — network
    const sendtoAddr = libc.findExportByName("sendto")
    if (sendtoAddr) {
      Interceptor.attach(sendtoAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const len = args[2].toInt32()
          const data = tryReadBuffer(args[1], len)
          log(LogType.Hook, NAME, `sendto: ${len} bytes${data ? `\n${data}` : ""}`)
        },
      })
      hookCount++
    }

    // recvfrom — network
    const recvfromAddr = libc.findExportByName("recvfrom")
    if (recvfromAddr) {
      Interceptor.attach(recvfromAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          ;(this as any)._buf = args[1]
          ;(this as any)._active = true
        },
        onLeave(retval) {
          if (!(this as any)._active) return
          const len = retval.toInt32()
          if (len <= 0) return
          const data = tryReadBuffer((this as any)._buf, len)
          log(LogType.Hook, NAME, `recvfrom: ${len} bytes${data ? `\n${data}` : ""}`)
        },
      })
      hookCount++
    }

    // __system_property_get — device info
    const syspropAddr = libc.findExportByName("__system_property_get")
    if (syspropAddr) {
      Interceptor.attach(syspropAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const prop = tryReadCString(args[0])
          if (prop) {
            ;(this as any)._prop = prop
            ;(this as any)._valueBuf = args[1]
          }
        },
        onLeave() {
          if (!(this as any)._prop) return
          const value = tryReadCString((this as any)._valueBuf)
          log(
            LogType.Hook,
            NAME,
            `__system_property_get: ${(this as any)._prop} = "${value || ""}"`,
          )
        },
      })
      hookCount++
    }

    // execve — process execution
    const execveAddr = libc.findExportByName("execve")
    if (execveAddr) {
      Interceptor.attach(execveAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const path = tryReadCString(args[0])
          if (path) {
            log(LogType.Info, NAME, `execve: ${path}`)
          }
        },
      })
      hookCount++
    }

    // popen — process execution
    const popenAddr = libc.findExportByName("popen")
    if (popenAddr) {
      Interceptor.attach(popenAddr, {
        onEnter(args) {
          if (!isFromTarget(this, targetModule)) return
          const cmd = tryReadCString(args[0])
          if (cmd) {
            log(LogType.Info, NAME, `popen: ${cmd}`)
          }
        },
      })
      hookCount++
    }

    log(
      LogType.Info,
      NAME,
      `Syscall hooks attached: ${hookCount} functions on libc.so (filtered to ${targetModule.name})`,
    )
  }

  // ── Public API ─────────────────────────────────────────────────────────

  export interface MonitorOptions {
    /** Skip libc syscall hooks (open, strstr, socket, etc.) to avoid crashes
     *  in heavily obfuscated native code that does internal file I/O */
    skipSyscalls?: boolean
  }

  function activateMonitor(targetLibrary: string, options?: MonitorOptions): void {
    const targetModule = Process.getModuleByName(targetLibrary)
    log(
      LogType.Info,
      NAME,
      `Monitoring ${targetLibrary} @ ${targetModule.base} (${targetModule.size} bytes)`,
    )

    hookJNI()
    hookLinker()
    if (!options?.skipSyscalls) {
      hookSyscalls(targetModule)
    } else {
      log(LogType.Info, NAME, `Syscall hooks skipped (skipSyscalls=true)`)
    }

    log(LogType.Info, NAME, `All hooks active for ${targetLibrary}`)
  }

  export function perform(targetLibrary: string, options?: MonitorOptions): void {
    // Check if already loaded
    try {
      Process.getModuleByName(targetLibrary)
      log(LogType.Info, NAME, `${targetLibrary} already loaded, attaching now`)
      activateMonitor(targetLibrary, options)
      return
    } catch {
      // Not loaded yet — intercept dlopen to catch it
    }

    log(LogType.Info, NAME, `Waiting for ${targetLibrary} via dlopen intercept...`)

    let activated = false

    // Hook both dlopen and android_dlopen_ext to catch the load
    for (const fnName of ["dlopen", "android_dlopen_ext"]) {
      let addr: NativePointer | null = null
      for (const mod of ["libdl.so", "linker64", "linker"]) {
        try {
          addr = Process.getModuleByName(mod).findExportByName(fnName)
          if (addr) break
        } catch {
          continue
        }
      }
      if (!addr) continue

      Interceptor.attach(addr, {
        onEnter(args) {
          const lib = tryReadCString(args[0])
          if (lib && lib.includes(targetLibrary)) {
            ;(this as any)._match = true
          }
        },
        onLeave() {
          if (!(this as any)._match || activated) return
          activated = true
          try {
            activateMonitor(targetLibrary, options)
          } catch (e) {
            log(LogType.Error, NAME, `Failed to activate after dlopen: ${e}`)
          }
        },
      })
    }
  }
}
