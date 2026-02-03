import Java from "frida-java-bridge"
import { log, logOnce, LogType, formatStackLog } from "../../utils/logger"
import { getStackTrace, AccessEntry } from "../../utils/functions"

/**
 * Network Monitor & Spoof
 * Spoofs network APIs via inlined class hooks,
 * plus additional monitoring hooks for NetworkInterface and URL connections.
 */
export namespace NetworkMonitor {
  const NAME = "[NetworkMonitor]"

  // ─── State ───────────────────────────────────────────────────────────

  let accessLog: AccessEntry[] = []

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
        `\n║ ├── Connections: URL.openConnection` +
        `\n║ ├── HTTP Headers: custom request headers` +
        `\n║ └── HTTP Response: status, content-type, length` +
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
      hookHTTPRequestHeaders()
      hookHTTPResponseMetadata()
    } catch (error) {
      log(LogType.Error, NAME, `Network hooks failed: \n${error}`)
    }
  }

  export function getAccessLog(): AccessEntry[] {
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

          const stack = getStackTrace()
          if (logOnce(LogType.Hook, NAME, `URL.openConnection: ${urlStr}${formatStackLog(stack)}`, domain)) {
            accessLog.push({ timestamp: Date.now(), api: "URL.openConnection", value: urlStr, stack })
          } else {
            log(LogType.Verbose, NAME, `URL.openConnection: ${urlStr} (repeat)`)
          }

          return this.openConnection(...args)
        }
      })

      log(LogType.Hook, NAME, `URL.openConnection monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `URL.openConnection hooks failed: ${error}`)
    }
  }

  // ─── HTTP Headers ────────────────────────────────────────────────────

  const STANDARD_HEADERS = new Set([
    "content-type", "accept", "user-agent", "host", "connection",
    "accept-encoding", "content-length", "accept-language",
    "cache-control", "cookie", "authorization", "transfer-encoding",
  ])

  function hookHTTPRequestHeaders(): void {
    try {
      const HttpURLConnection = Java.use("java.net.HttpURLConnection")

      HttpURLConnection.setRequestProperty.implementation = function (key: any, value: any) {
        try {
          const keyStr = key ? key.toString() : ""
          const keyLower = keyStr.toLowerCase()

          if (!STANDARD_HEADERS.has(keyLower)) {
            let url = ""
            try {
              url = this.getURL().toString()
            } catch (_) {
              url = "[unknown]"
            }
            const stack = getStackTrace()
            const dedupKey = `header:${url}:${keyLower}`

            if (logOnce(LogType.Hook, NAME, `[HTTP Header] ${url}\n  ${keyStr}: ${value}${formatStackLog(stack)}`, dedupKey)) {
              accessLog.push({ timestamp: Date.now(), api: "HTTP.setRequestProperty", value: `${url} ${keyStr}: ${value}`, stack })
            }
          }
        } catch (e) {
          log(LogType.Debug, NAME, `HTTP header logging failed: ${e}`)
        }

        return this.setRequestProperty(key, value)
      }

      log(LogType.Hook, NAME, `HTTP request header monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `HTTP request header hooks failed: ${error}`)
    }
  }

  // ─── HTTP Response ──────────────────────────────────────────────────

  function hookHTTPResponseMetadata(): void {
    try {
      const HttpURLConnection = Java.use("java.net.HttpURLConnection")

      HttpURLConnection.getResponseCode.implementation = function () {
        const code = this.getResponseCode()

        try {
          let url = ""
          try { url = this.getURL().toString() } catch (_) { url = "[unknown]" }

          let contentType = ""
          try { contentType = this.getContentType() || "" } catch (_) { contentType = "[error]" }

          let contentLength = -1
          try { contentLength = this.getContentLength() } catch (_) { /* ignore */ }

          const dedupKey = `response:${url}`

          if (logOnce(LogType.Hook, NAME, `[HTTP Response] ${url} status=${code} type=${contentType} length=${contentLength}`, dedupKey)) {
            accessLog.push({ timestamp: Date.now(), api: "HTTP.getResponseCode", value: `${url} status=${code} type=${contentType} length=${contentLength}`, stack: "" })
          }
        } catch (e) {
          log(LogType.Debug, NAME, `HTTP response logging failed: ${e}`)
        }

        return code
      }

      log(LogType.Hook, NAME, `HTTP response metadata monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `HTTP response metadata hooks failed: ${error}`)
    }
  }

  // ─── Utilities ───────────────────────────────────────────────────────

  function recordAccess(api: string, value: string, stack: string): void {
    accessLog.push({ timestamp: Date.now(), api, value, stack })
    log(LogType.Hook, NAME, `${api}: ${value}${formatStackLog(stack)}`)
  }
}
