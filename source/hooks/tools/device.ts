import Java from "frida-java-bridge"
import { log, LogType } from "../../utils/logger"
import { Country } from "../../utils/enums"
import {
  setActiveCountry,
  getActiveProfile,
  getSecureSettings,
  getGlobalSettings,
} from "../../utils/types"

/**
 * Device Spoofing
 * Spoofs device hardware identity, system settings, and misc device checks.
 * Requires an active country profile.
 */
export namespace DeviceSpoofing {
  const NAME = "[DeviceSpoofing]"

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Device Spoofing \x1b[0m` +
        `\n║ ├── Hardware: Build, MediaDrm, Sensor` +
        `\n║ ├── Context: ContextImpl` +
        `\n║ ├── WebKit: WebView (User-Agent)` +
        `\n║ ├── Settings: SettingsSecure, SettingsGlobal` +
        `\n║ └── Intent: Battery status` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(country?: Country): void {
    if (country) {
      setActiveCountry(country)
    }
    const profile = getActiveProfile()
    log(LogType.Info, NAME, `Profile: ${profile.device.MODEL} / ${profile.telephony.operatorName}`)
    info()
    try {
      hookBuild()
      hookMediaDrm()
      hookSensor()
      hookContextImpl()
      hookWebView()
      hookSettingsSecure()
      hookSettingsGlobal()
      hookIntent()
    } catch (error) {
      log(LogType.Error, NAME, `Hooks failed: \n${error}`)
    }
  }

  // ─── Intent handleIntent (exported for Activity hook in antiemulation) ──

  const spoofedBattery = {
    level: 75,
    status: 2, // BATTERY_STATUS_CHARGING
    scale: 100,
    plugType: 1, // BATTERY_PLUGGED_AC
  }

  function isRelevantIntent(action: string, pkg: string, data: string): boolean {
    let isRelevant = false
    if (pkg && pkg === "com.google.android.apps.maps") {
      isRelevant = true
    }
    if (data && (data.startsWith("waze://?ll=") || data.startsWith("tel:"))) {
      isRelevant = true
    }
    if (action && action.startsWith("android.intent.action.DIAL")) {
      isRelevant = true
    }
    return isRelevant
  }

  export function handleIntent(intent: any): boolean {
    try {
      const action = intent.getAction()
      const pkg = intent.getPackage()
      const data = intent.getDataString()
      let extrasString = ""
      const isIntentRelevant = isRelevantIntent(action, pkg, data)

      if (isIntentRelevant) {
        log(LogType.Verbose, NAME, "Relevant intent detected, logging details...")
        const extras = intent.getExtras()
        if (extras) {
          try {
            const keys = extras.keySet()
            const iterator = keys.iterator()
            while (iterator.hasNext()) {
              const key = iterator.next().toString()
              extrasString += intent.getStringExtra(key)
            }
          } catch (error) {
            log(LogType.Verbose, NAME, `Problem iterating extras: ${error}`)
          }
        }

        log(
          LogType.Verbose,
          NAME,
          `Intent details - Action: ${action}, Package: ${pkg}, Data: ${data}, Extras: ${extrasString}`,
        )
      }

      return isIntentRelevant
    } catch (error) {
      log(LogType.Verbose, NAME, `handleIntent error: ${error}`)
      return false
    }
  }

  // ─── Build ────────────────────────────────────────────────────────────

  function hookBuild(): void {
    try {
      const Build = Java.use("android.os.Build")
      const BuildVersion = Java.use("android.os.Build$VERSION")
      const profile = getActiveProfile()

      // Hook Build static fields
      for (const [key, value] of Object.entries(profile.device)) {
        if (key === "ANDROID_ID" || key === "GSF_ID") continue
        try {
          Build[key].value = value
          log(LogType.Verbose, NAME, `Build.${key} spoofed to: ${value}`)
        } catch (error) {
          log(LogType.Verbose, NAME, `Failed to spoof Build.${key}: ${error}`)
        }
      }

      // Hook VERSION static fields
      for (const [key, value] of Object.entries(profile.version)) {
        try {
          BuildVersion[key].value = value
          log(LogType.Verbose, NAME, `Build.VERSION.${key} spoofed to: ${value}`)
        } catch (error) {
          log(LogType.Verbose, NAME, `Failed to spoof Build.VERSION.${key}: ${error}`)
        }
      }

      // Hook Build methods
      Build.getRadioVersion.implementation = function () {
        const ret = this.getRadioVersion()
        log(LogType.Info, NAME, `Build.getRadioVersion: ${ret} -> ${profile.device.RADIO}`)
        return profile.device.RADIO
      }

      Build.getSerial.implementation = function () {
        const ret = this.getSerial()
        log(LogType.Info, NAME, `Build.getSerial: ${ret} -> ${profile.device.SERIAL}`)
        return profile.device.SERIAL
      }
    } catch (error) {
      log(LogType.Error, NAME, `Build hook failed: ${error}`)
    }
  }

  // ─── MediaDrm ─────────────────────────────────────────────────────────

  function hookMediaDrm(): void {
    try {
      const MediaDrm = Java.use("android.media.MediaDrm")
      const drm = getActiveProfile().drm

      MediaDrm.getPropertyString.implementation = function (propertyName: string) {
        const ret = this.getPropertyString(propertyName)

        switch (propertyName) {
          case "vendor":
            log(
              LogType.Verbose,
              NAME,
              `MediaDrm.getPropertyString: ${propertyName} -> ${drm.vendor}`,
            )
            return drm.vendor
          case "version":
            log(
              LogType.Verbose,
              NAME,
              `MediaDrm.getPropertyString: ${propertyName} -> ${drm.version}`,
            )
            return drm.version
          case "description":
            log(
              LogType.Verbose,
              NAME,
              `MediaDrm.getPropertyString: ${propertyName} -> ${drm.description}`,
            )
            return drm.description
          case "deviceUniqueId":
            log(
              LogType.Verbose,
              NAME,
              `MediaDrm.getPropertyString: ${propertyName} -> 0123456789abcdef`,
            )
            return "0123456789abcdef"
          default:
            return ret
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `MediaDrm hook failed: ${error}`)
    }
  }

  // ─── Sensor ───────────────────────────────────────────────────────────

  function hookSensor(): void {
    try {
      const Sensor = Java.use("android.hardware.Sensor")

      // Hook getName to clean up emulator-specific sensor names
      Sensor.getName.implementation = function () {
        const ret = this.getName()
        if (ret.includes("Goldfish")) {
          const spoofed = ret.replace("Goldfish ", "")
          log(LogType.Verbose, NAME, `Sensor.getName: ${ret} -> ${spoofed}`)
          return spoofed
        }
        return ret
      }

      // Hook getVendor to clean up emulator-specific vendor names
      Sensor.getVendor.implementation = function () {
        const ret = this.getVendor()
        if (ret.includes("The Android Open Source Project") || ret.includes("AOSP")) {
          const spoofed = ret
            .replace("The Android Open Source Project", "Sensors Inc.")
            .replace("AOSP", "Sensors Inc.")
          log(LogType.Verbose, NAME, `Sensor.getVendor: ${ret} -> ${spoofed}`)
          return spoofed
        }
        return ret
      }

      // Hook toString to clean up sensor descriptions
      ;(Sensor.toString as any).implementation = function () {
        const ret = this.toString()
        if (
          ret.includes("Goldfish") ||
          ret.includes("The Android Open Source Project") ||
          ret.includes("AOSP")
        ) {
          const spoofed = ret
            .replace(/Goldfish /g, "")
            .replace(/The Android Open Source Project/g, "Sensors Inc.")
            .replace(/AOSP/g, "Sensors Inc.")
          log(LogType.Verbose, NAME, `Sensor.toString: cleaned up sensor description`)
          return spoofed
        }
        return ret
      }
    } catch (error) {
      log(LogType.Error, NAME, `Sensor hook failed: ${error}`)
    }
  }

  // ─── ContextImpl ──────────────────────────────────────────────────────

  function hookContextImpl(): void {
    try {
      const ContextImpl = Java.use("android.app.ContextImpl")

      ContextImpl.checkSelfPermission.overload("java.lang.String").implementation = function (
        permission: string,
      ) {
        const result = this.checkSelfPermission(permission)
        log(LogType.Verbose, NAME, `Context.checkSelfPermission: ${permission} -> ${result}`)
        return result
      }

      ContextImpl.checkPermission.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const result = this.checkPermission(...args)
          log(LogType.Verbose, NAME, `Context.checkPermission: ${args[0]} -> ${result}`)
          return result
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `ContextImpl hook failed: ${error}`)
    }
  }

  // ─── WebView ──────────────────────────────────────────────────────────

  function hookWebView(): void {
    try {
      const WebView = Java.use("android.webkit.WebView")
      const spoofedUA = getActiveProfile().userAgent

      if (WebView.getUserAgentString) {
        WebView.getUserAgentString.overloads.forEach((overload: any) => {
          overload.implementation = function (...args: any) {
            const ret = this.getUserAgentString(...args)
            if (
              ret.includes("Android SDK built for x86") ||
              ret.includes("Emulator") ||
              ret.includes("generic")
            ) {
              log(LogType.Verbose, NAME, `WebView.getUserAgentString: spoofed emulator UA`)
              return spoofedUA
            }
            return ret
          }
        })
        log(LogType.Verbose, NAME, "WebView.getUserAgentString overloads hooked successfully")
      } else {
        log(LogType.Verbose, NAME, "getUserAgentString method not found in WebView, skipping hook")
      }
    } catch (error) {
      log(LogType.Error, NAME, `WebView hook failed: ${error}`)
    }
  }

  // ─── Settings.Secure ──────────────────────────────────────────────────

  function hookSettingsSecure(): void {
    try {
      const SettingsSecure = Java.use("android.provider.Settings$Secure")
      const secureSettings = getSecureSettings()

      // getString hooks
      SettingsSecure.getString.overload(
        "android.content.ContentResolver",
        "java.lang.String",
      ).implementation = function (cr: any, name: string) {
        const ret = this.getString(cr, name)

        switch (name) {
          case "android_id":
            log(
              LogType.Info,
              NAME,
              `Settings.Secure.getString: ${name} -> ${secureSettings.android_id}`,
            )
            return secureSettings.android_id
          case "mock_location":
            log(
              LogType.Info,
              NAME,
              `Settings.Secure.getString: ${name} -> ${secureSettings.mock_location}`,
            )
            return secureSettings.mock_location
          default:
            return ret
        }
      }

      // getInt hooks
      SettingsSecure.getInt.overload(
        "android.content.ContentResolver",
        "java.lang.String",
        "int",
      ).implementation = function (cr: any, name: string, defaultValue: number) {
        const ret = this.getInt(cr, name, defaultValue)

        switch (name) {
          case "auto_time":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Secure.getInt: ${name} -> ${secureSettings.auto_time}`,
            )
            return secureSettings.auto_time
          case "development_settings_enabled":
            log(
              LogType.Info,
              NAME,
              `Settings.Secure.getInt: ${name} -> ${secureSettings.development_settings_enabled}`,
            )
            return secureSettings.development_settings_enabled
          case "adb_enabled":
            log(
              LogType.Info,
              NAME,
              `Settings.Secure.getInt: ${name} -> ${secureSettings.adb_enabled}`,
            )
            return secureSettings.adb_enabled
          case "airplane_mode_on":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Secure.getInt: ${name} -> ${secureSettings.airplane_mode_on}`,
            )
            return secureSettings.airplane_mode_on
          default:
            return ret
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `SettingsSecure hook failed: ${error}`)
    }
  }

  // ─── Settings.Global ──────────────────────────────────────────────────

  function hookSettingsGlobal(): void {
    try {
      const SettingsGlobal = Java.use("android.provider.Settings$Global")
      const globalSettings = getGlobalSettings()

      SettingsGlobal.getInt.overload(
        "android.content.ContentResolver",
        "java.lang.String",
        "int",
      ).implementation = function (cr: any, name: string, number: number) {
        const ret = this.getInt(cr, name, number)

        switch (name) {
          case "development_settings_enabled":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Global.getInt: ${name} -> ${globalSettings.development_settings_enabled}`,
            )
            return globalSettings.development_settings_enabled
          case "adb_enabled":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Global.getInt: ${name} -> ${globalSettings.adb_enabled}`,
            )
            return globalSettings.adb_enabled
          case "auto_time":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Global.getInt: ${name} -> ${globalSettings.auto_time}`,
            )
            return globalSettings.auto_time
          case "auto_time_zone":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Global.getInt: ${name} -> ${globalSettings.auto_time_zone}`,
            )
            return globalSettings.auto_time_zone
          case "stay_on_while_plugged_in":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Global.getInt: ${name} -> ${globalSettings.stay_on_while_plugged_in}`,
            )
            return globalSettings.stay_on_while_plugged_in
          case "mobile_data":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Global.getInt: ${name} -> ${globalSettings.mobile_data}`,
            )
            return globalSettings.mobile_data
          case "airplane_mode_on":
            log(
              LogType.Verbose,
              NAME,
              `Settings.Global.getInt: ${name} -> ${globalSettings.airplane_mode_on}`,
            )
            return globalSettings.airplane_mode_on
          default:
            return ret
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `SettingsGlobal hook failed: ${error}`)
    }
  }

  // ─── Intent ───────────────────────────────────────────────────────────

  function hookIntent(): void {
    try {
      const Intent = Java.use("android.content.Intent")

      // Hook getIntExtra for battery status spoofing
      Intent.getIntExtra.overload("java.lang.String", "int").implementation = function (
        name: string,
        defaultValue: number,
      ) {
        const ret = this.getIntExtra(name, defaultValue)
        const action = this.getAction()

        if (action === "android.intent.action.BATTERY_CHANGED") {
          switch (name) {
            case "level":
              log(
                LogType.Verbose,
                NAME,
                `Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.level}`,
              )
              return spoofedBattery.level
            case "status":
              log(
                LogType.Verbose,
                NAME,
                `Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.status}`,
              )
              return spoofedBattery.status
            case "scale":
              log(
                LogType.Verbose,
                NAME,
                `Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.scale}`,
              )
              return spoofedBattery.scale
            case "plugged":
              log(
                LogType.Verbose,
                NAME,
                `Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.plugType}`,
              )
              return spoofedBattery.plugType
          }
        }

        return ret
      }

      // Hook resolveActivity for intent monitoring
      Intent.resolveActivity.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          try {
            log(LogType.Verbose, NAME, `Intent.resolveActivity called`)
            handleIntent(this)
          } catch (error) {
            log(LogType.Verbose, NAME, `Intent.resolveActivity monitoring error: ${error}`)
          }
          return this.resolveActivity(...args)
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `Intent hook failed: ${error}`)
    }
  }
}
