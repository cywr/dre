import { log, LogType } from "../../utils/logger"

/**
 * Generic native method hooking utility for Frida
 * Provides a flexible interface to hook native library methods with customizable callbacks
 */
export namespace Native {
  const NAME = "[Native]"
  export interface HookConfig {
    library: string
    method: string
    onEnter?: (args: NativePointer[], context: any) => void
    onLeave?: (retval: NativePointer, context: any) => void
  }

  /**
   * Wait for a library to be loaded and execute code when ready
   * @param libraryName Name of the library to wait for
   * @param operation Function to execute once library is loaded
   * @param retryInterval Milliseconds between retries (default: 1000)
   * @param maxRetries Maximum retry attempts (default: -1 for unlimited)
   * @returns Promise that resolves with the operation result
   */
  export function waitLibrary<T>(
    libraryName: string,
    operation: () => T | Promise<T>,
    retryInterval: number = 1000,
    maxRetries: number = -1,
  ): Promise<T> {
    let retryCount = 0

    const tryOperation = (): Promise<T> => {
      return new Promise((resolve, reject) => {
        try {
          // Check if library is loaded
          try {
            Process.getModuleByName(libraryName)
          } catch {
            if (maxRetries !== -1 && retryCount >= maxRetries) {
              reject(new Error(`Max retries (${maxRetries}) reached for library '${libraryName}'`))
              return
            }

            retryCount++
            log(
              LogType.Debug,
              NAME,
              `Library '${libraryName}' not loaded yet, retrying in ${retryInterval}ms (attempt ${retryCount})`,
            )
            setTimeout(() => {
              tryOperation().then(resolve).catch(reject)
            }, retryInterval)
            return
          }

          // Library is loaded, execute operation
          const result = operation()
          if (result instanceof Promise) {
            result.then(resolve).catch(reject)
          } else {
            resolve(result)
          }
        } catch (error) {
          reject(error)
        }
      })
    }

    return tryOperation()
  }

  /**
   * Hook a native method from a specified library
   * @param config Configuration object containing library, method, and callbacks
   */
  export function attach(config: HookConfig): void {
    try {
      // Find the method
      let address
      try {
        const module = Process.getModuleByName(config.library)
        address = module.getExportByName(config.method)
      } catch (findError) {
        throw new Error(
          `Export lookup failed for ${config.library}::${config.method}: ${findError}`,
        )
      }

      if (!address) {
        throw new Error(`Method '${config.method}' not found in library '${config.library}'`)
      }

      try {
        Interceptor.attach(address, {
          onEnter: function (args) {
            log(LogType.Hook, NAME, `→ Entering ${config.library}::${config.method}`)

            if (config.onEnter) {
              try {
                config.onEnter(args, this)
              } catch (error) {
                log(LogType.Error, NAME, `onEnter callback error: ${error}`)
              }
            }
          },
          onLeave: function (retval) {
            log(
              LogType.Hook,
              NAME,
              `← Leaving ${config.library}::${config.method} with return value: ${retval}`,
            )

            if (config.onLeave) {
              try {
                config.onLeave(retval, this)
              } catch (error) {
                log(LogType.Error, NAME, `onLeave callback error: ${error}`)
              }
            }
          },
        })

        log(LogType.Hook, NAME, `✓ Hook ready for ${config.library}::${config.method}`)
      } catch (attachError) {
        throw new Error(
          `Interceptor.attach failed for ${config.library}::${config.method}: ${attachError}`,
        )
      }
    } catch (error) {
      log(LogType.Error, NAME, `Failed to hook ${config.library}::${config.method}: ${error}`)
    }
  }

  /**
   * Hook multiple methods at once
   * @param configs Array of hook configurations
   */
  export function attachMany(configs: HookConfig[]): void {
    configs.forEach((config) => attach(config))
  }

  /**
   * Actively call a native function and return its result
   * @param library Library name
   * @param method Function name
   * @param returnType Return type (e.g., 'pointer', 'int', 'void')
   * @param argTypes Array of argument types (e.g., ['int', 'pointer'])
   * @param args Array of arguments to pass to the function
   * @returns The function's return value
   */
  export function call(
    library: string,
    method: string,
    returnType: string = "pointer",
    argTypes: string[] = [],
    args: any[] = [],
  ): any {
    // Get the function address
    let address
    try {
      const module = Process.getModuleByName(library)
      address = module.getExportByName(method)
    } catch (findError) {
      throw new Error(`Export lookup failed for ${library}::${method}: ${findError}`)
    }

    if (!address) {
      throw new Error(`Method '${method}' not found in library '${library}'`)
    }

    log(LogType.Hook, NAME, `Calling ${library}::${method}(${args.join(", ")}) -> ${returnType}`)

    // Create NativeFunction and call it
    const fn = new NativeFunction(address, returnType as any, argTypes as any)
    const result = (fn as any)(...args)

    log(LogType.Hook, NAME, `${library}::${method} returned: ${result}`)
    return result
  }

  /**
   * Call a native function that returns a pointer and dump its memory
   * @param library Library name
   * @param method Function name
   * @param dumpSize Number of bytes to dump from returned pointer (default: 256)
   * @param argTypes Array of argument types (default: [])
   * @param args Array of arguments (default: [])
   */
  export function callAndDump(
    library: string,
    method: string,
    dumpSize: number = 256,
    argTypes: string[] = [],
    args: any[] = [],
  ): any {
    try {
      const result = call(library, method, "pointer", argTypes, args)

      if (result && !result.isNull()) {
        log(
          LogType.Hook,
          NAME,
          `${method} memory dump (${dumpSize} bytes): \n \n${hexDump(result, dumpSize)}\n `,
        )
      } else {
        log(LogType.Hook, NAME, `${method} returned NULL pointer`)
      }
      return result
    } catch (error) {
      log(LogType.Error, NAME, `callAndDump failed: ${error}`)
      throw error
    }
  }

  /**
   * Helper function to read a C string from a pointer
   * @param ptr Pointer to the string
   * @returns String content or null if invalid
   */
  export function readCString(ptr: NativePointer): string | null {
    try {
      return ptr.readCString()
    } catch (error) {
      log(LogType.Error, NAME, `Failed to read C string: ${error}`)
      return null
    }
  }

  /**
   * Helper function to read UTF-8 string from a pointer
   * @param ptr Pointer to the string
   * @param length Optional length parameter
   * @returns String content or null if invalid
   */
  export function readUtf8String(ptr: NativePointer, length?: number): string | null {
    try {
      return length ? ptr.readUtf8String(length) : ptr.readUtf8String()
    } catch (error) {
      log(LogType.Error, NAME, `Failed to read UTF-8 string: ${error}`)
      return null
    }
  }

  /**
   * Helper function to dump memory as hex
   * @param ptr Pointer to memory
   * @param size Size in bytes
   * @returns Hex dump string
   */
  export function hexDump(ptr: NativePointer, size: number): string {
    try {
      return hexdump(ptr, { length: size, ansi: false })
    } catch (error) {
      log(LogType.Error, NAME, `Failed to hex dump: ${error}`)
      return ""
    }
  }

  /**
   * Helper function to get the base address of a module
   * @param moduleName Name of the module
   * @returns Base address or null if not found
   */
  export function getModuleBase(moduleName: string): NativePointer | null {
    try {
      const module = Process.findModuleByName(moduleName)
      return module ? module.base : null
    } catch (error) {
      log(LogType.Error, NAME, `Failed to get module base for '${moduleName}': ${error}`)
      return null
    }
  }

  /**
   * List all exported functions from a library
   * @param libraryName Name of the library
   * @returns Array of export names
   */
  export function listExports(libraryName: string): string[] {
    const module = Process.getModuleByName(libraryName)
    const exports = module.enumerateExports()
    const exportNames = exports
      .map((exp) => exp.name)
      .filter((name: string | null) => name !== null)

    log(LogType.Hook, NAME, `Found ${exportNames.length} exports in ${libraryName}`)
    log(
      LogType.Hook,
      NAME,
      `Exports: ${exportNames.slice(0, 10).join(", ")}${exportNames.length > 10 ? "..." : ""}`,
    )

    return exportNames
  }

  /**
   * List all imported functions from a library
   * @param libraryName Name of the library
   * @returns Array of import names
   */
  export function listImports(libraryName: string): string[] {
    const module = Process.getModuleByName(libraryName)
    const imports = module.enumerateImports()
    const importNames = imports
      .map((imp) => imp.name)
      .filter((name: string | null) => name !== null)

    log(LogType.Hook, NAME, `Found ${importNames.length} imports in ${libraryName}`)
    log(
      LogType.Hook,
      NAME,
      `Imports: ${importNames.slice(0, 10).join(", ")}${importNames.length > 10 ? "..." : ""}`,
    )

    return importNames
  }

  /**
   * Search for functions matching a pattern in a library
   * @param libraryName Name of the library
   * @param pattern Search pattern (supports partial matches)
   * @returns Array of matching export names
   */
  export function findExports(libraryName: string, pattern: string): string[] {
    try {
      const exports = listExports(libraryName)
      const matches = exports.filter((name) => name.includes(pattern))
      log(
        LogType.Hook,
        NAME,
        `Found ${matches.length} exports matching '${pattern}' in ${libraryName}: ${matches.join(", ")}`,
      )
      return matches
    } catch (error) {
      log(LogType.Error, NAME, `Failed to search exports in '${libraryName}': ${error}`)
      return []
    }
  }
}
