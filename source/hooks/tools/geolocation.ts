import Java from "frida-java-bridge"
import { log, logOnce, LogType, formatStackLog } from "../../utils/logger"
import { getStackTrace, AccessEntry } from "../../utils/functions"
import { Country } from "../../utils/enums"
import { setActiveCountry, getActiveProfile } from "../../utils/types"

/**
 * Geolocation Monitor & Spoof
 * Spoofs geo APIs using country profile via class hooks,
 * plus additional monitoring hooks for Locale and TimeZone.
 */
export namespace Geolocation {
  const NAME = "[Geolocation]"

  // ─── State ───────────────────────────────────────────────────────────

  let accessLog: AccessEntry[] = []

  // ─── Public ──────────────────────────────────────────────────────────

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Geolocation Monitor & Spoof \x1b[0m` +
        `\n║ ├── Telephony: TelephonyManager (MCC/MNC, carrier)` +
        `\n║ ├── Location: Location, LocationManager` +
        `\n║ ├── Resources: Resources, ResourcesImpl (config)` +
        `\n║ ├── Locale: getDefault, getCountry, getLanguage` +
        `\n║ └── TimeZone: getDefault, getID` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(country?: Country): void {
    if (country) setActiveCountry(country)
    info()
    try {
      // Spoof via inlined class hooks
      hookTelephonyManager()
      hookLocation()
      hookLocationManager()
      hookResources()
      hookResourcesImpl()
      // Additional monitoring (non-overlapping APIs)
      hookLocale()
      hookTimeZone()
    } catch (error) {
      log(LogType.Error, NAME, `Geolocation hooks failed: \n${error}`)
    }
  }

  export function getAccessLog(): AccessEntry[] {
    return accessLog
  }

  // ─── TelephonyManager ─────────────────────────────────────────────────

  function hookTelephonyManager(): void {
    try {
      const TelephonyManager = Java.use("android.telephony.TelephonyManager")
      const telephony = getActiveProfile().telephony
      const operator = telephony.mcc + telephony.mnc

      // Network types
      TelephonyManager.getNetworkType.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getNetworkType(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getNetworkType: ${ret} -> ${telephony.networkType}`,
          )
          return telephony.networkType
        }
      })

      TelephonyManager.getDataNetworkType.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getDataNetworkType(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getDataNetworkType: ${ret} -> ${telephony.dataNetworkType}`,
          )
          return telephony.dataNetworkType
        }
      })

      // Operators
      TelephonyManager.getNetworkOperator.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getNetworkOperator(...args)
          log(LogType.Verbose, NAME, `TelephonyManager.getNetworkOperator: ${ret} -> ${operator}`)
          return operator
        }
      })

      TelephonyManager.getNetworkOperatorName.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getNetworkOperatorName(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getNetworkOperatorName: ${ret} -> ${telephony.operatorName}`,
          )
          return telephony.operatorName
        }
      })

      // SIM Operator methods
      TelephonyManager.getSimOperator.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getSimOperator(...args)
          log(LogType.Verbose, NAME, `TelephonyManager.getSimOperator: ${ret} -> ${operator}`)
          return operator
        }
      })

      TelephonyManager.getSimOperatorName.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getSimOperatorName(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getSimOperatorName: ${ret} -> ${telephony.operatorName}`,
          )
          return telephony.operatorName
        }
      })

      TelephonyManager.getNetworkCountryIso.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getNetworkCountryIso(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getNetworkCountryIso: ${ret} -> ${telephony.countryIso}`,
          )
          return telephony.countryIso
        }
      })

      TelephonyManager.getSimCountryIso.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getSimCountryIso(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getSimCountryIso: ${ret} -> ${telephony.countryIso}`,
          )
          return telephony.countryIso
        }
      })

      // SIM State
      TelephonyManager.getSimState.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getSimState(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getSimState: ${ret} -> ${telephony.simState}`,
          )
          return telephony.simState
        }
      })

      // Phone number
      TelephonyManager.getLine1Number.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getLine1Number(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getLine1Number: ${ret} -> ${telephony.phoneNumber}`,
          )
          return telephony.phoneNumber
        }
      })

      // IMSI (Subscriber ID)
      TelephonyManager.getSubscriberId.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getSubscriberId(...args)
          log(
            LogType.Verbose,
            NAME,
            `TelephonyManager.getSubscriberId: ${ret} -> ${telephony.imsi}`,
          )
          return telephony.imsi
        }
      })
    } catch (error) {
      log(LogType.Error, NAME, `TelephonyManager hook failed: ${error}`)
    }
  }

  // ─── Location ─────────────────────────────────────────────────────────

  function hookLocation(): void {
    try {
      const Location = Java.use("android.location.Location")
      const spoofedLocation = getActiveProfile().location

      Location.getLatitude.implementation = function () {
        const ret = this.getLatitude()
        log(LogType.Verbose, NAME, `Location.getLatitude: ${ret} -> ${spoofedLocation.latitude}`)
        return spoofedLocation.latitude
      }

      Location.getLongitude.implementation = function () {
        const ret = this.getLongitude()
        log(LogType.Verbose, NAME, `Location.getLongitude: ${ret} -> ${spoofedLocation.longitude}`)
        return spoofedLocation.longitude
      }

      Location.getAltitude.implementation = function () {
        const ret = this.getAltitude()
        log(LogType.Verbose, NAME, `Location.getAltitude: ${ret} -> ${spoofedLocation.altitude}`)
        return spoofedLocation.altitude
      }

      Location.getAccuracy.implementation = function () {
        const ret = this.getAccuracy()
        log(LogType.Verbose, NAME, `Location.getAccuracy: ${ret} -> ${spoofedLocation.accuracy}`)
        return spoofedLocation.accuracy
      }

      Location.getProvider.implementation = function () {
        const ret = this.getProvider()
        log(LogType.Verbose, NAME, `Location.getProvider: ${ret} -> ${spoofedLocation.provider}`)
        return spoofedLocation.provider
      }
    } catch (error) {
      log(LogType.Error, NAME, `Location hook failed: ${error}`)
    }
  }

  // ─── LocationManager ──────────────────────────────────────────────────

  function hookLocationManager(): void {
    try {
      const LocationManager = Java.use("android.location.LocationManager")

      LocationManager.isProviderEnabled.overload("java.lang.String").implementation = function (
        provider: string,
      ) {
        const ret = this.isProviderEnabled(provider)
        if (provider === "gps" || provider === "network") {
          log(LogType.Verbose, NAME, `LocationManager.isProviderEnabled: ${provider} -> true`)
          return true
        }
        return ret
      }
    } catch (error) {
      log(LogType.Error, NAME, `LocationManager hook failed: ${error}`)
    }
  }

  // ─── Resources ────────────────────────────────────────────────────────

  function hookResources(): void {
    try {
      const Resources = Java.use("android.content.res.Resources")
      const profile = getActiveProfile()

      // Hook getConfiguration for MCC/MNC spoofing
      Resources.getConfiguration.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const ret = this.getConfiguration(...args)

          const oldMcc = ret.mcc.value
          const newMcc = parseInt(profile.telephony.mcc)
          ret.mcc.value = newMcc
          log(LogType.Verbose, NAME, `Resources.getConfiguration: mcc ${oldMcc} -> ${newMcc}`)

          const oldMnc = ret.mnc.value
          const newMnc = parseInt(profile.telephony.mnc)
          ret.mnc.value = newMnc
          log(LogType.Verbose, NAME, `Resources.getConfiguration: mnc ${oldMnc} -> ${newMnc}`)

          return ret
        }
      })

      // Hook getDisplayMetrics to spoof display metrics
      Resources.getDisplayMetrics.implementation = function () {
        const ret = this.getDisplayMetrics()
        try {
          ret.density.value = profile.display.density
          ret.densityDpi.value = profile.display.densityDpi
          ret.widthPixels.value = profile.display.widthPixels
          ret.heightPixels.value = profile.display.heightPixels
          ret.scaledDensity.value = profile.display.scaledDensity
          ret.xdpi.value = profile.display.xdpi
          ret.ydpi.value = profile.display.ydpi
          log(
            LogType.Verbose,
            NAME,
            `Resources.getDisplayMetrics: spoofed to ${profile.device.MODEL} metrics`,
          )
        } catch (error) {
          log(LogType.Verbose, NAME, `Failed to spoof display metrics: ${error}`)
        }
        return ret
      }

      // Hook getString to monitor potentially revealing strings
      Resources.getString.overload("int").implementation = function (id: number) {
        const ret = this.getString(id)
        if (
          ret &&
          (ret.includes("emulator") || ret.includes("goldfish") || ret.includes("generic"))
        ) {
          log(LogType.Verbose, NAME, `Resources.getString: potentially revealing string: ${ret}`)
        }
        return ret
      }
    } catch (error) {
      log(LogType.Error, NAME, `Resources hook failed: ${error}`)
    }
  }

  // ─── ResourcesImpl ────────────────────────────────────────────────────

  function hookResourcesImpl(): void {
    try {
      const ResourcesImpl = Java.use("android.content.res.ResourcesImpl")
      const profile = getActiveProfile()

      ResourcesImpl.getDisplayMetrics.implementation = function () {
        const ret = this.getDisplayMetrics()
        try {
          ret.density.value = profile.display.density
          ret.densityDpi.value = profile.display.densityDpi
          ret.widthPixels.value = profile.display.widthPixels
          ret.heightPixels.value = profile.display.heightPixels
          ret.scaledDensity.value = profile.display.scaledDensity
          ret.xdpi.value = profile.display.xdpi
          ret.ydpi.value = profile.display.ydpi
          log(
            LogType.Verbose,
            NAME,
            `ResourcesImpl.getDisplayMetrics: spoofed to ${profile.device.MODEL} metrics`,
          )
        } catch (error) {
          log(LogType.Verbose, NAME, `Failed to spoof impl display metrics: ${error}`)
        }
        return ret
      }
    } catch (error) {
      log(LogType.Error, NAME, `ResourcesImpl hook failed: ${error}`)
    }
  }

  // ─── Locale & TimeZone Spoofing ──────────────────────────────────────

  function hookLocale(): void {
    try {
      const Locale = Java.use("java.util.Locale")
      const profile = getActiveProfile()
      const lang = profile.locale.language
      const country = profile.locale.country

      try {
        Locale.getDefault.overload().implementation = function () {
          const result = this.getDefault()
          const spoofed = Locale.$new(lang, country)
          const stack = getStackTrace()
          if (isAppCaller(stack)) {
            recordAccess("Locale.getDefault", `${result} -> ${lang}_${country}`, stack)
          }
          return spoofed
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook Locale.getDefault: ${e}`)
      }

      try {
        Locale.getDefault.overload("java.util.Locale$Category").implementation = function (
          category: any,
        ) {
          const result = this.getDefault(category)
          const spoofed = Locale.$new(lang, country)
          const stack = getStackTrace()
          if (isAppCaller(stack)) {
            recordAccess("Locale.getDefault(Category)", `${result} -> ${lang}_${country}`, stack)
          }
          return spoofed
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook Locale.getDefault(Category): ${e}`)
      }

      try {
        Locale.getCountry.implementation = function () {
          const result = this.getCountry()
          log(LogType.Verbose, NAME, `Locale.getCountry: ${result} -> ${country}`)
          return country
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook Locale.getCountry: ${e}`)
      }

      try {
        Locale.getLanguage.implementation = function () {
          const result = this.getLanguage()
          log(LogType.Verbose, NAME, `Locale.getLanguage: ${result} -> ${lang}`)
          return lang
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook Locale.getLanguage: ${e}`)
      }

      log(LogType.Hook, NAME, `Locale spoofing enabled: ${lang}_${country}`)
    } catch (error) {
      log(LogType.Debug, NAME, `Locale hooks failed: ${error}`)
    }
  }

  function hookTimeZone(): void {
    try {
      const TimeZone = Java.use("java.util.TimeZone")
      const profile = getActiveProfile()
      const tzId = profile.timezone

      try {
        TimeZone.getDefault.implementation = function () {
          const result = this.getDefault()
          const spoofed = TimeZone.getTimeZone(tzId)
          const stack = getStackTrace()
          if (isAppCaller(stack)) {
            recordAccess("TimeZone.getDefault", `${result.getID()} -> ${tzId}`, stack)
          }
          return spoofed
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook TimeZone.getDefault: ${e}`)
      }

      try {
        TimeZone.getID.implementation = function () {
          const result = this.getID()
          const stack = getStackTrace()
          if (isAppCaller(stack)) {
            recordAccess("TimeZone.getID", `${result} -> ${tzId}`, stack)
          }
          return tzId
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook TimeZone.getID: ${e}`)
      }

      log(LogType.Hook, NAME, `TimeZone spoofing enabled: ${tzId}`)
    } catch (error) {
      log(LogType.Debug, NAME, `TimeZone hooks failed: ${error}`)
    }
  }

  // ─── Utilities ───────────────────────────────────────────────────────

  function isAppCaller(stack: string): boolean {
    const frameworkPrefixes = [
      "android.",
      "java.",
      "javax.",
      "androidx.",
      "com.android.",
      "dalvik.",
      "libcore.",
    ]
    const lines = stack.split("\n").slice(0, 5)
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.length === 0) continue
      let isFramework = false
      for (const prefix of frameworkPrefixes) {
        if (trimmed.startsWith(prefix)) {
          isFramework = true
          break
        }
      }
      if (!isFramework) {
        return true
      }
    }
    return false
  }

  function recordAccess(api: string, value: string, stack: string): void {
    accessLog.push({ timestamp: Date.now(), api, value, stack })
    logOnce(LogType.Hook, NAME, `${api}: ${value}${formatStackLog(stack)}`, `${api}:${value}`)
  }
}
