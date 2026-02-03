import { log, logOnce, LogType } from "../../utils/logger"
import * as Utils from "../../utils/functions"
import { DexExtractor } from "../../utils/dexextractor"
import Java from "frida-java-bridge"

/**
 * Hook for android.util.Base64 class to intercept Base64 encoding/decoding operations.
 */
export namespace Base64 {
  const NAME = "[Base64]"
  const MAX_LOG_LEN = 200

  function truncate(s: string): string {
    if (s.length <= MAX_LOG_LEN) return s
    return s.substring(0, MAX_LOG_LEN) + `... (${s.length} chars)`
  }

  export function perform(): void {
    try {
      decode()
      encode()
    } catch (error) {
      log(LogType.Error, NAME, `Hooks failed: ${error}`)
    }
  }

  function decode() {
    const Base64 = Java.use("android.util.Base64")

    Base64.decode.overloads.forEach((overload: any) => {
      overload.implementation = function (...args: any) {
        var output = this.decode(...args)

        // Handle different argument patterns for logging
        if (args.length === 2) {
          // decode(string/byte[], flags) - args[0] could be string or byte array
          const input = typeof args[0] === "string" ? args[0] : Utils.bin2ascii(args[0])
          const key = input.substring(0, 64)
          logOnce(
            LogType.Hook,
            NAME,
            `Base64.decode\n - Input: ${truncate(input)}\n - Output: ${truncate(Utils.bin2ascii(output))}`,
            key,
          )
        } else if (args.length === 4) {
          // decode(byte[], offset, length, flags)
          const input = Utils.bin2ascii(args[0])
          const key = input.substring(0, 64)
          logOnce(
            LogType.Hook,
            NAME,
            `Base64.decode\n - Input: ${truncate(input)}\n - Output: ${truncate(Utils.bin2ascii(output))}`,
            key,
          )
        }

        // Check if output is DEX and extract if so
        if (DexExtractor.isDexFile(output)) {
          DexExtractor.saveDexFile(output, "Base64", "decode")
        }

        return output
      }
    })
  }

  function encode() {
    const Base64 = Java.use("android.util.Base64")

    Base64.encode.overloads.forEach((overload: any) => {
      overload.implementation = function (...args: any) {
        var output = this.encode(...args)
        const input = Utils.bin2ascii(args[0])
        const key = input.substring(0, 64)
        logOnce(
          LogType.Hook,
          NAME,
          `Base64.encode\n - Input: ${truncate(input)}\n - Output: ${truncate(Utils.bin2ascii(output))}`,
          key,
        )

        // Check if input or output is DEX and extract if so
        if (DexExtractor.isDexFile(args[0])) {
          DexExtractor.saveDexFile(args[0], "Base64", "encode_input")
        }
        if (DexExtractor.isDexFile(output)) {
          DexExtractor.saveDexFile(output, "Base64", "encode_output")
        }

        return output
      }
    })

    Base64.encodeToString.overloads.forEach((overload: any) => {
      overload.implementation = function (...args: any) {
        var output = this.encodeToString(...args)
        const input = Utils.bin2ascii(args[0])
        const key = input.substring(0, 64)
        logOnce(
          LogType.Hook,
          NAME,
          `Base64.encodeToString\n - Input: ${truncate(input)}\n - Output: ${truncate(output)}`,
          key,
        )

        // Check if input is DEX and extract if so
        if (DexExtractor.isDexFile(args[0])) {
          DexExtractor.saveDexFile(args[0], "Base64", "encodeToString")
        }

        return output
      }
    })
  }
}
