import { log, LogType } from "../../utils/logger"
import Java from "frida-java-bridge"

/**
 * Attribution & Install Referrer Monitor
 * Detects apps using AppsFlyer conversion data and Google Install Referrer
 * to dynamically load WebView content. Purely observational — monitors and logs only.
 *
 * NOTE: Java.enumerateLoadedClasses and Java.enumerateClassLoaders are avoided
 * because they cause ART interpreter crashes (SIGSEGV in ExecuteSwitchImplCpp)
 * on Android 13 ARM64 with Frida 17.6.2. All class lookups use direct Java.use()
 * with try/catch instead.
 */
export namespace Attribution {
  const NAME = "[Attribution]"

  // ─── State ───────────────────────────────────────────────────────────

  let lastConversionData: any = null
  let lastReferrerString: string | null = null

  const AF_KEYS_OF_INTEREST = new Set([
    "af_status",
    "campaign",
    "media_source",
    "af_dp",
    "af_web_dp",
    "adset",
    "adgroup",
    "af_channel",
    "af_ad",
    "af_adset",
    "is_first_launch",
    "click_time",
    "install_time",
    "af_siteid",
    "af_sub1",
    "af_sub2",
    "af_sub3",
    "af_sub4",
    "af_sub5",
  ])

  // ─── Public ──────────────────────────────────────────────────────────

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m Attribution & Install Referrer Monitor \x1b[0m` +
        `\n║ ├── AppsFlyer: init, start, ConversionListener (via init callback)` +
        `\n║ ├── Google Install Referrer: Client, ReferrerDetails` +
        `\n║ └── WebView Correlation: loadUrl, loadDataWithBaseURL, addJavascriptInterface` +
        `\n╙──────────────────────────────────────────────────────────────────────────────┘`,
    )
  }

  export function perform(enableMapMonitoring: boolean = false): void {
    info()

    // Section 1: AppsFlyer Direct Hooks (no class enumeration)
    hookAppsFlyerDirect()

    if (enableMapMonitoring) {
      hookMapGetForAttributionKeys()
    }

    // Section 2: Google Install Referrer Hooks (no class enumeration)
    hookInstallReferrerDirect()

    // Section 3: WebView URL Monitoring
    hookWebViewLoadUrl()
    hookWebViewLoadDataWithBaseURL()
    hookWebViewAddJavascriptInterface()
  }

  // ─── Section 1: AppsFlyer Direct ─────────────────────────────────────

  function hookAppsFlyerDirect(): void {
    try {
      const AppsFlyerLib = Java.use("com.appsflyer.AppsFlyerLib")

      // Hook init — also captures ConversionListener when passed as arg
      AppsFlyerLib.init.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const devKey = args[0]
          const listener = args[1]
          log(
            LogType.Hook,
            NAME,
            `AppsFlyerLib.init() called` +
              `\n  Dev Key: ${devKey}` +
              `\n  Listener: ${listener ? listener.$className : "null"}` +
              `\n  Stack: ${getStackTrace()}`,
          )

          // Hook the listener instance if provided
          if (listener) {
            try {
              const listenerClass = Java.cast(listener, Java.use("java.lang.Object")).$className
              const cls = Java.use(listenerClass)
              hookListenerMethods(cls, listenerClass)
            } catch (e) {
              log(LogType.Debug, NAME, `Could not hook listener from init: ${e}`)
            }
          }

          return this.init(...args)
        }
      })

      // Hook start
      AppsFlyerLib.start.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          log(LogType.Hook, NAME, `AppsFlyerLib.start() called`)
          return this.start(...args)
        }
      })

      log(LogType.Hook, NAME, `AppsFlyer SDK hooked`)
    } catch (e) {
      log(LogType.Debug, NAME, `AppsFlyer SDK not found (app may not use it)`)
    }
  }

  function hookListenerMethods(cls: any, className: string): void {
    try {
      cls.onConversionDataSuccess.implementation = function (data: any) {
        lastConversionData = data
        log(
          LogType.Hook,
          NAME,
          `[CONVERSION DATA] ${className}.onConversionDataSuccess()` +
            `\n  ${dumpJavaMap(data)}` +
            `\n  Stack: ${getStackTrace()}`,
        )
        return this.onConversionDataSuccess(data)
      }
    } catch (e) {
      log(LogType.Debug, NAME, `Could not hook onConversionDataSuccess on ${className}: ${e}`)
    }

    try {
      cls.onConversionDataFail.implementation = function (error: any) {
        log(LogType.Hook, NAME, `[CONVERSION DATA] ${className}.onConversionDataFail(): ${error}`)
        return this.onConversionDataFail(error)
      }
    } catch (e) {
      log(LogType.Debug, NAME, `Could not hook onConversionDataFail on ${className}: ${e}`)
    }

    try {
      cls.onAppOpenAttribution.implementation = function (data: any) {
        log(
          LogType.Hook,
          NAME,
          `[DEEP LINK] ${className}.onAppOpenAttribution()` + `\n  ${dumpJavaMap(data)}`,
        )
        return this.onAppOpenAttribution(data)
      }
    } catch (e) {
      log(LogType.Debug, NAME, `Could not hook onAppOpenAttribution on ${className}: ${e}`)
    }

    try {
      cls.onAttributionFailure.implementation = function (error: any) {
        log(LogType.Hook, NAME, `[DEEP LINK] ${className}.onAttributionFailure(): ${error}`)
        return this.onAttributionFailure(error)
      }
    } catch (e) {
      log(LogType.Debug, NAME, `Could not hook onAttributionFailure on ${className}: ${e}`)
    }

    log(LogType.Hook, NAME, `ConversionListener methods hooked on ${className}`)
  }

  function hookMapGetForAttributionKeys(): void {
    try {
      const HashMap = Java.use("java.util.HashMap")

      HashMap.get.implementation = function (key: any) {
        const result = this.get(key)
        if (key !== null) {
          const keyStr = key.toString()
          if (AF_KEYS_OF_INTEREST.has(keyStr)) {
            log(
              LogType.Hook,
              NAME,
              `[MAP KEY] HashMap.get("${keyStr}") = ${result}` + `\n  Stack: ${getStackTrace()}`,
            )
          }
        }
        return result
      }

      log(LogType.Hook, NAME, `HashMap.get() attribution key monitoring enabled`)
    } catch (error) {
      log(LogType.Debug, NAME, `HashMap.get() monitoring failed: ${error}`)
    }
  }

  // ─── Section 2: Google Install Referrer ──────────────────────────────

  function hookInstallReferrerDirect(): void {
    try {
      const InstallReferrerClient = Java.use(
        "com.android.installreferrer.api.InstallReferrerClient",
      )

      InstallReferrerClient.startConnection.implementation = function (listener: any) {
        log(
          LogType.Hook,
          NAME,
          `InstallReferrerClient.startConnection()` +
            `\n  Listener: ${listener ? listener.$className : "null"}`,
        )

        // Hook the listener's callback
        if (listener) {
          try {
            hookInstallReferrerStateListener(listener)
          } catch (e) {
            log(LogType.Debug, NAME, `Could not hook referrer state listener: ${e}`)
          }
        }

        return this.startConnection(listener)
      }

      log(LogType.Hook, NAME, `InstallReferrerClient.startConnection hooked`)
    } catch (e) {
      // Try ReferrerDetails separately — the client class may not exist
      // but the details class might be available
    }

    try {
      const ReferrerDetails = Java.use("com.android.installreferrer.api.ReferrerDetails")

      try {
        ReferrerDetails.getInstallReferrer.implementation = function () {
          const referrer = this.getInstallReferrer()
          lastReferrerString = referrer ? referrer.toString() : null
          log(
            LogType.Hook,
            NAME,
            `[REFERRER] ReferrerDetails.getInstallReferrer(): ${referrer}` +
              `\n  Stack: ${getStackTrace()}`,
          )
          return referrer
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getInstallReferrer: ${e}`)
      }

      try {
        ReferrerDetails.getReferrerClickTimestampSeconds.implementation = function () {
          const ts = this.getReferrerClickTimestampSeconds()
          log(LogType.Hook, NAME, `ReferrerDetails.getReferrerClickTimestampSeconds(): ${ts}`)
          return ts
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getReferrerClickTimestampSeconds: ${e}`)
      }

      try {
        ReferrerDetails.getInstallBeginTimestampSeconds.implementation = function () {
          const ts = this.getInstallBeginTimestampSeconds()
          log(LogType.Hook, NAME, `ReferrerDetails.getInstallBeginTimestampSeconds(): ${ts}`)
          return ts
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getInstallBeginTimestampSeconds: ${e}`)
      }

      log(LogType.Hook, NAME, `ReferrerDetails hooked`)
    } catch (e) {
      log(LogType.Debug, NAME, `Install Referrer SDK not found (app may not use it)`)
    }
  }

  function hookInstallReferrerStateListener(listener: any): void {
    const listenerClassName = Java.cast(listener, Java.use("java.lang.Object")).$className
    const listenerCls = Java.use(listenerClassName)

    const RESPONSE_CODES: Record<number, string> = {
      0: "OK",
      1: "SERVICE_UNAVAILABLE",
      2: "FEATURE_NOT_SUPPORTED",
      [-1]: "SERVICE_DISCONNECTED",
    }

    try {
      listenerCls.onInstallReferrerSetupFinished.implementation = function (responseCode: number) {
        const codeName = RESPONSE_CODES[responseCode] || `UNKNOWN(${responseCode})`
        log(
          LogType.Hook,
          NAME,
          `InstallReferrerStateListener.onInstallReferrerSetupFinished(): ${codeName} (${responseCode})`,
        )
        return this.onInstallReferrerSetupFinished(responseCode)
      }

      log(LogType.Hook, NAME, `InstallReferrerStateListener hooked on ${listenerClassName}`)
    } catch (e) {
      log(
        LogType.Debug,
        NAME,
        `Could not hook onInstallReferrerSetupFinished on ${listenerClassName}: ${e}`,
      )
    }
  }

  // ─── Section 3: WebView URL Monitoring ───────────────────────────────

  function hookWebViewLoadUrl(): void {
    try {
      const WebView = Java.use("android.webkit.WebView")

      WebView.loadUrl.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const url = args[0]
          log(LogType.Hook, NAME, `WebView.loadUrl(): ${url}` + `\n  Stack: ${getStackTrace()}`)
          logCorrelation(url ? url.toString() : "")
          return this.loadUrl(...args)
        }
      })

      log(LogType.Hook, NAME, `WebView.loadUrl hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `WebView.loadUrl hook failed: ${error}`)
    }
  }

  function hookWebViewLoadDataWithBaseURL(): void {
    try {
      const WebView = Java.use("android.webkit.WebView")

      WebView.loadDataWithBaseURL.implementation = function (
        baseUrl: any,
        data: any,
        mimeType: any,
        encoding: any,
        historyUrl: any,
      ) {
        const dataStr = data ? data.toString() : ""
        const snippet = dataStr.length > 500 ? dataStr.substring(0, 500) + "..." : dataStr
        log(
          LogType.Hook,
          NAME,
          `WebView.loadDataWithBaseURL()` +
            `\n  Base URL: ${baseUrl}` +
            `\n  MIME: ${mimeType}` +
            `\n  Data (first 500): ${snippet}`,
        )
        logCorrelation(baseUrl ? baseUrl.toString() : "")
        return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl)
      }

      log(LogType.Hook, NAME, `WebView.loadDataWithBaseURL hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `WebView.loadDataWithBaseURL hook failed: ${error}`)
    }
  }

  function hookWebViewAddJavascriptInterface(): void {
    try {
      const WebView = Java.use("android.webkit.WebView")

      WebView.addJavascriptInterface.implementation = function (obj: any, name: any) {
        const objClass = obj ? Java.cast(obj, Java.use("java.lang.Object")).$className : "null"
        log(
          LogType.Hook,
          NAME,
          `WebView.addJavascriptInterface()` +
            `\n  Bridge name: ${name}` +
            `\n  Object class: ${objClass}`,
        )
        return this.addJavascriptInterface(obj, name)
      }

      log(LogType.Hook, NAME, `WebView.addJavascriptInterface hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `WebView.addJavascriptInterface hook failed: ${error}`)
    }
  }

  // ─── Utilities ───────────────────────────────────────────────────────

  function dumpJavaMap(map: any): string {
    try {
      const entries: string[] = []
      const entrySet = map.entrySet()
      const iterator = entrySet.iterator()

      while (iterator.hasNext()) {
        const entry = iterator.next()
        entries.push(`${entry.getKey()} = ${entry.getValue()}`)
      }

      return entries.join("\n  ")
    } catch (e) {
      return `[Could not dump map: ${e}]`
    }
  }

  function getStackTrace(): string {
    try {
      const Exception = Java.use("java.lang.Exception")
      const exception = Exception.$new()
      const stackElements = exception.getStackTrace()
      const frames: string[] = []
      const maxFrames = Math.min(stackElements.length, 15)

      for (let i = 0; i < maxFrames; i++) {
        frames.push(stackElements[i].toString())
      }

      return frames.join("\n    ")
    } catch (e) {
      return `[Could not get stack trace: ${e}]`
    }
  }

  function logCorrelation(url: string): void {
    if (!url) return

    if (lastConversionData || lastReferrerString) {
      log(
        LogType.Hook,
        NAME,
        `[CORRELATION] WebView URL loaded after attribution data received` +
          `\n  URL: ${url}` +
          (lastConversionData ? `\n  Has conversion data: yes` : "") +
          (lastReferrerString ? `\n  Last referrer: ${lastReferrerString}` : ""),
      )
    }

    if (lastReferrerString && url.includes(lastReferrerString)) {
      log(
        LogType.Hook,
        NAME,
        `[CORRELATION MATCH] WebView URL contains referrer string!` +
          `\n  URL: ${url}` +
          `\n  Referrer: ${lastReferrerString}`,
      )
    }
  }
}
