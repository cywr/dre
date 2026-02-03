import Java from "frida-java-bridge"
import { log, LogType } from "../../utils/logger"

/**
 * Network Monitor & Spoof
 * Spoofs network APIs via inlined class hooks,
 * plus additional monitoring hooks for NetworkInterface and URL connections.
 */
export namespace NetworkMonitor {
  const NAME = "[NetworkMonitor]"

  // ─── State ───────────────────────────────────────────────────────────

  interface NetAccessEntry {
    timestamp: number
    api: string
    value: string
    stack: string
  }

  let accessLog: NetAccessEntry[] = []
  let seenDomains = new Set<string>()

  // ─── Public ──────────────────────────────────────────────────────────

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Network Monitor & Spoof \x1b[0m` +
        `\n║ ├── Connectivity: ConnectivityManager, NetworkInfo` +
        `\n║ ├── WiFi: WifiInfo` +
        `\n║ ├── DNS: InetAddress` +
        `\n║ ├── Interfaces: NetworkInterface` +
        `\n║ └── Connections: URL.openConnection` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(): void {
    info()
    try {
      // Spoof via inlined class hooks
      hookConnectivityManager()
      hookNetworkInfo()
      hookWifiInfo()
      hookInetAddress()
      // Additional monitoring (non-overlapping APIs)
      hookNetworkInterface()
      hookURLConnection()
    } catch (error) {
      log(LogType.Error, NAME, `Network hooks failed: \n${error}`)
    }
  }

  export function getAccessLog(): NetAccessEntry[] {
    return accessLog
  }

  // ─── ConnectivityManager ──────────────────────────────────────────────

  function hookConnectivityManager(): void {
    try {
      const ConnectivityManager = Java.use("android.net.ConnectivityManager")

      ConnectivityManager.getMobileDataEnabled.implementation = function () {
        const ret = this.getMobileDataEnabled()
        log(LogType.Verbose, NAME, `ConnectivityManager.getMobileDataEnabled: ${ret} -> true`)
        return true
      }
    } catch (error) {
      log(LogType.Error, NAME, `ConnectivityManager hook failed: ${error}`)
    }
  }

  // ─── NetworkInfo ──────────────────────────────────────────────────────

  function hookNetworkInfo(): void {
    try {
      const NetworkInfo = Java.use("android.net.NetworkInfo")

      NetworkInfo.getType.implementation = function () {
        const ret = this.getType()
        log(LogType.Verbose, NAME, `NetworkInfo.getType: ${ret} -> 1 (WIFI)`)
        return 1
      }

      NetworkInfo.getTypeName.implementation = function () {
        const ret = this.getTypeName()
        log(LogType.Verbose, NAME, `NetworkInfo.getTypeName: ${ret} -> WIFI`)
        return "WIFI"
      }

      NetworkInfo.getSubtype.implementation = function () {
        const ret = this.getSubtype()
        log(LogType.Verbose, NAME, `NetworkInfo.getSubtype: ${ret} -> -1`)
        return -1
      }
    } catch (error) {
      log(LogType.Error, NAME, `NetworkInfo hook failed: ${error}`)
    }
  }

  // ─── WifiInfo ─────────────────────────────────────────────────────────

  function hookWifiInfo(): void {
    try {
      const WifiInfo = Java.use("android.net.wifi.WifiInfo")

      WifiInfo.getSSID.implementation = function () {
        const ret = this.getSSID()
        log(LogType.Verbose, NAME, `WifiInfo.getSSID: ${ret} -> "AndroidWifi"`)
        return '"AndroidWifi"'
      }

      WifiInfo.getBSSID.implementation = function () {
        const ret = this.getBSSID()
        log(LogType.Verbose, NAME, `WifiInfo.getBSSID: ${ret} -> 02:00:00:00:00:00`)
        return "02:00:00:00:00:00"
      }

      WifiInfo.getMacAddress.implementation = function () {
        const ret = this.getMacAddress()
        log(LogType.Verbose, NAME, `WifiInfo.getMacAddress: ${ret} -> 02:00:00:00:00:00`)
        return "02:00:00:00:00:00"
      }
    } catch (error) {
      log(LogType.Error, NAME, `WifiInfo hook failed: ${error}`)
    }
  }

  // ─── InetAddress ──────────────────────────────────────────────────────

  function hookInetAddress(): void {
    try {
      const InetAddress = Java.use("java.net.InetAddress")

      InetAddress.getHostAddress.implementation = function () {
        const ret = this.getHostAddress()
        if (
          ret !== "127.0.0.1" &&
          !ret.startsWith("192.168.") &&
          !ret.startsWith("10.") &&
          !ret.startsWith("172.")
        ) {
          log(LogType.Verbose, NAME, `InetAddress.getHostAddress: ${ret} -> 8.8.8.8`)
          return "8.8.8.8"
        }
        return ret
      }

      InetAddress.getHostName.implementation = function () {
        const ret = this.getHostName()
        const address = this.getHostAddress()
        if (
          address !== "127.0.0.1" &&
          !address.startsWith("192.168.") &&
          !address.startsWith("10.") &&
          !address.startsWith("172.")
        ) {
          log(LogType.Verbose, NAME, `InetAddress.getHostName: ${ret} -> dns.google`)
          return "dns.google"
        }
        return ret
      }
    } catch (error) {
      log(LogType.Error, NAME, `InetAddress hook failed: ${error}`)
    }
  }

  // ─── Monitor Hooks (non-overlapping with class hooks) ──────────────

  function hookNetworkInterface(): void {
    try {
      const NetworkInterface = Java.use("java.net.NetworkInterface")

      try {
        NetworkInterface.getNetworkInterfaces.implementation = function () {
          const result = this.getNetworkInterfaces()
          const stack = getStackTrace()

          // Log interface details then re-wrap the Enumeration
          try {
            const Collections = Java.use("java.util.Collections")
            const ArrayList = Java.use("java.util.ArrayList")
            const list = ArrayList.$new()

            const tempList = Collections.list(result)
            const size = tempList.size()
            const ifaceNames: string[] = []

            for (let i = 0; i < size; i++) {
              const iface = Java.cast(tempList.get(i), NetworkInterface)
              const name = iface.getName()
              const hwAddr = iface.getHardwareAddress()
              let mac = "null"
              if (hwAddr !== null) {
                const bytes = Java.array("byte", hwAddr)
                const parts: string[] = []
                for (let j = 0; j < bytes.length; j++) {
                  parts.push(("0" + (bytes[j] & 0xff).toString(16)).slice(-2))
                }
                mac = parts.join(":")
              }
              ifaceNames.push(`${name}(${mac})`)
              list.add(tempList.get(i))
            }

            recordAccess(
              "NetworkInterface.getNetworkInterfaces",
              `interfaces=[${ifaceNames.join(", ")}]`,
              stack,
            )

            // Re-wrap as Enumeration
            return Collections.enumeration(list)
          } catch (e) {
            recordAccess("NetworkInterface.getNetworkInterfaces", "[enumeration error]", stack)
            return result
          }
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook NetworkInterface.getNetworkInterfaces: ${e}`)
      }

      try {
        NetworkInterface.getHardwareAddress.implementation = function () {
          const result = this.getHardwareAddress()
          const stack = getStackTrace()
          let mac = "null"
          if (result !== null) {
            const bytes = Java.array("byte", result)
            const parts: string[] = []
            for (let j = 0; j < bytes.length; j++) {
              parts.push(("0" + (bytes[j] & 0xff).toString(16)).slice(-2))
            }
            mac = parts.join(":")
          }
          recordAccess(`NetworkInterface.getHardwareAddress(${this.getName()})`, mac, stack)
          return result
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook NetworkInterface.getHardwareAddress: ${e}`)
      }

      log(LogType.Hook, NAME, `NetworkInterface monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `NetworkInterface hooks failed: ${error}`)
    }
  }

  function hookURLConnection(): void {
    try {
      const URL = Java.use("java.net.URL")

      URL.openConnection.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const urlStr = this.toString()
          let domain = ""
          try {
            domain = this.getHost()
          } catch (e) {
            domain = urlStr
          }

          if (!seenDomains.has(domain)) {
            seenDomains.add(domain)
            const stack = getStackTrace()
            recordAccess("URL.openConnection", `domain=${domain}`, stack)
          } else {
            log(LogType.Verbose, NAME, `URL.openConnection: ${domain} (repeat)`)
          }

          return this.openConnection(...args)
        }
      })

      log(LogType.Hook, NAME, `URL.openConnection monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `URL.openConnection hooks failed: ${error}`)
    }
  }

  // ─── Utilities ───────────────────────────────────────────────────────

  function getStackTrace(): string {
    try {
      const Exception = Java.use("java.lang.Exception")
      const exception = Exception.$new()
      const stackElements = exception.getStackTrace()
      const frames: string[] = []
      const maxFrames = Math.min(stackElements.length, 10)
      for (let i = 0; i < maxFrames; i++) {
        frames.push(stackElements[i].toString())
      }
      return frames.join("\n    ")
    } catch (e) {
      return `[Could not get stack trace: ${e}]`
    }
  }

  function recordAccess(api: string, value: string, stack: string): void {
    accessLog.push({
      timestamp: Date.now(),
      api,
      value,
      stack,
    })
    log(LogType.Hook, NAME, `${api}: ${value}\n    Stack: ${stack}`)
  }
}
