import Java from "frida-java-bridge"
import { log, LogType } from "../../utils/logger"
import { SENSOR_VENDOR_REPLACEMENTS, DRM_UUIDS } from "../../utils/enums"
import { DeviceSpoofing } from "./device"

/**
 * Anti-Emulation Detection Bypass
 * Bypasses emulator detection via sensor, activity, system property, and UUID checks.
 */
export namespace AntiEmulation {
  const NAME = "[AntiEmulation]"

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Anti-Emulation Detection Bypass \x1b[0m` +
        `\n║ ├── Sensors: SensorManager` +
        `\n║ ├── Activity: Activity monitoring` +
        `\n║ ├── System: System property spoofing` +
        `\n║ └── DRM: UUID manipulation` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(): void {
    info()
    try {
      hookSensorManager()
      hookActivity()
      hookSystem()
      hookUUID()
    } catch (error) {
      log(LogType.Error, NAME, `Hooks failed: \n${error}`)
    }
  }

  // ─── SensorManager ────────────────────────────────────────────────────

  function hookSensorManager(sensors?: any): void {
    try {
      const AndroidVersion = Java.use("android.os.Build$VERSION")

      if (AndroidVersion.SDK_INT.value > 30) {
        // Android 11+ solution
        try {
          const SensorManager = Java.use("android.hardware.SensorManager")
          const Sensor = Java.use("android.hardware.Sensor")
          const InputSensorInfo = Java.use("android.hardware.input.InputSensorInfo")

          try {
            SensorManager.getSensorList.overload("int").implementation = function (type: any) {
              log(LogType.Debug, NAME, `getSensorList(${type}) called`)

              if (sensors && Array.isArray(sensors)) {
                const ret = Java.use("java.util.ArrayList").$new()

                for (let i = 0; i < sensors.length; i++) {
                  const sensor = sensors[i]

                  if (type === -1 || type === sensor.type) {
                    log(LogType.Verbose, NAME, `Setting up sensor: ${sensor.name}`)
                    ret.add(
                      Sensor.$new(
                        InputSensorInfo.$new(
                          sensor.name,
                          sensor.vendor,
                          sensor.version,
                          0,
                          sensor.type,
                          sensor.maximumRange,
                          sensor.resolution,
                          sensor.power,
                          sensor.minDelay,
                          sensor.fifoReservedEventCount,
                          sensor.fifoMaxEventCount,
                          sensor.stringType,
                          "",
                          sensor.maxDelay,
                          1,
                          sensor.id,
                        ),
                      ),
                    )
                  }
                }

                return ret
              } else {
                // Fall back to original implementation if no sensors provided
                return this.getSensorList(type)
              }
            }
          } catch (error) {
            log(LogType.Error, NAME, `getSensorList hook failed: ${error}`)
          }
        } catch (error) {
          log(LogType.Error, NAME, `Android 11+ antiEmulation failed: ${error}`)
        }
      } else {
        // Android 10 and below solution
        try {
          const Sensor = Java.use("android.hardware.Sensor")

          try {
            Sensor.getName.implementation = function () {
              const name = this.getName()
              let spoof = name

              for (const [pattern, replacement] of Object.entries(SENSOR_VENDOR_REPLACEMENTS)) {
                spoof = spoof.replace(new RegExp(pattern, "g"), replacement)
              }

              log(LogType.Debug, NAME, `getName: ${name} -> ${spoof}`)
              return spoof
            }
          } catch (error) {
            log(LogType.Error, NAME, `getName hook failed: ${error}`)
          }

          try {
            ;(Sensor.toString as any).implementation = function () {
              const name = this.toString()
              let spoof = name

              for (const [pattern, replacement] of Object.entries(SENSOR_VENDOR_REPLACEMENTS)) {
                spoof = spoof.replace(new RegExp(pattern, "g"), replacement)
              }

              log(LogType.Debug, NAME, `toString: ${name} -> ${spoof}`)
              return spoof
            }
          } catch (error) {
            log(LogType.Error, NAME, `toString hook failed: ${error}`)
          }

          try {
            Sensor.getVendor.implementation = function () {
              const vendor = this.getVendor()
              let spoof = vendor

              for (const [pattern, replacement] of Object.entries(SENSOR_VENDOR_REPLACEMENTS)) {
                if (pattern !== "Goldfish ") {
                  // Skip Goldfish replacement for vendor
                  spoof = spoof.replace(new RegExp(pattern, "g"), replacement)
                }
              }

              log(LogType.Debug, NAME, `getVendor: ${vendor} -> ${spoof}`)
              return spoof
            }
          } catch (error) {
            log(LogType.Error, NAME, `getVendor hook failed: ${error}`)
          }
        } catch (error) {
          log(LogType.Error, NAME, `Android 10- antiEmulation failed: ${error}`)
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `SensorManager hook failed: ${error}`)
    }
  }

  // ─── Activity ─────────────────────────────────────────────────────────

  function hookActivity(): void {
    try {
      const Activity = Java.use("android.app.Activity")

      Activity.startActivity.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          try {
            const intent = args[0]
            log(LogType.Debug, NAME, `startActivity called with intent: ${intent}`)

            if (!DeviceSpoofing.handleIntent(intent)) {
              return this.startActivity(...args)
            }
          } catch (error) {
            log(LogType.Debug, NAME, `startActivity monitoring error: ${error}`)
          }
        }
      })

      Activity.finish.overloads.forEach((overload: any) => {
        overload.implementation = function () {
          log(LogType.Info, NAME, "finish() - bypassing app termination")
          return
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `Activity hook failed: ${error}`)
    }
  }

  // ─── System ───────────────────────────────────────────────────────────

  // Basic device spoofing properties
  const spoofedProperties: Record<string, string> = {
    "os.arch": "aarch64",
    "os.name": "Linux",
    "java.vm.version": "2.1.0",
    "java.vm.name": "ART",
    "java.vm.vendor": "The Android Open Source Project",
    "java.specification.version": "0.9",
    "java.specification.name": "Dalvik Core Library",
    "java.specification.vendor": "The Android Open Source Project",
    "java.version": "0",
    "java.vendor": "The Android Open Source Project",
    "java.vendor.url": "http://www.android.com/",
    "java.class.version": "50.0",
    "java.class.path": ".",
  }

  function hookSystem(): void {
    try {
      hookSystemProperties()
      hookNativeLibraries()
      hookGetEnvironment()
    } catch (error) {
      log(LogType.Error, NAME, `System hook failed: ${error}`)
    }
  }

  function hookSystemProperties(): void {
    try {
      const System = Java.use("java.lang.System")

      System.getProperty.overload("java.lang.String").implementation = function (name: string) {
        const spoofed = spoofedProperties[name]

        if (spoofed) {
          log(LogType.Debug, NAME, `getProperty: ${name} -> ${spoofed}`)
          return spoofed
        }

        // Generate basic user agent for http.agent property
        if (name === "http.agent") {
          const ua = "Dalvik/2.1.0 (Linux; U; Android 12; SM-G991B Build/SP1A.210812.016)"
          log(LogType.Debug, NAME, `getProperty (UserAgent): ${name} -> ${ua}`)
          return ua
        }

        return this.getProperty.call(this, name)
      }
    } catch (error) {
      log(LogType.Error, NAME, `System.getProperty hook failed: ${error}`)
    }
  }

  function hookNativeLibraries(): void {
    try {
      log(LogType.Verbose, NAME, "Hooking System.loadLibrary() overloads...")

      const System = Java.use("java.lang.System")
      const Runtime = Java.use("java.lang.Runtime")
      const VMStack = Java.use("dalvik.system.VMStack")
      const VERSION = Java.use("android.os.Build$VERSION")

      System.loadLibrary.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          log(LogType.Debug, NAME, `JNI loadLibrary: ${args[0]}`)

          try {
            if (VERSION.SDK_INT.value >= 29) {
              Runtime.getRuntime().loadLibrary0(
                Java.use("sun.reflect.Reflection").getCallerClass(),
                args[0],
              )
            } else if (VERSION.SDK_INT.value >= 24) {
              Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), args[0])
            } else {
              Runtime.getRuntime().loadLibrary(args[0], VMStack.getCallingClassLoader())
            }
          } catch (error) {
            log(LogType.Debug, NAME, `loadLibrary implementation error: ${error}`)
            return this.loadLibrary(...args)
          }
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `System.loadLibrary hook failed: ${error}`)
    }
  }

  function hookGetEnvironment(): void {
    try {
      const System = Java.use("java.lang.System")

      System.getenv.overload().implementation = function () {
        const ret = this.getenv()
        const Collections = Java.use("java.util.Collections")

        log(LogType.Debug, NAME, "getenv: returning empty map for security")
        return Collections.emptyMap()
      }
    } catch (error) {
      log(LogType.Error, NAME, `System.getenv hook failed: ${error}`)
    }
  }

  // ─── UUID ─────────────────────────────────────────────────────────────

  function hookUUID(): void {
    try {
      const UUID = Java.use("java.util.UUID")

      try {
        UUID.fromString.overload("java.lang.String").implementation = function (data: any) {
          const result = this.fromString(data)

          switch (data) {
            case DRM_UUIDS.WIDEVINE:
              log(
                LogType.Debug,
                NAME,
                `fromString(${data}) -> Returning ClearKey CDM UUID instead of Widevine CDM UUID`,
              )
              return this.fromString(DRM_UUIDS.CLEARKEY)
            default:
              break
          }

          log(LogType.Debug, NAME, `fromString(${data}) -> ${result.toString()}`)
          return result
        }
      } catch (error) {
        log(LogType.Error, NAME, `UUID.fromString hook failed: ${error}`)
      }
    } catch (error) {
      log(LogType.Error, NAME, `UUID hook failed: ${error}`)
    }
  }
}
