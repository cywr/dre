import Java from "frida-java-bridge"
import { log, LogType, formatStackLog } from "../../utils/logger"
import { getStackTrace, AccessEntry } from "../../utils/functions"
import { getActiveProfile } from "../../utils/types"

/**
 * PII Watcher
 * Monitors app access to personally identifiable information:
 * contacts, call logs, SMS, calendar, media, bookmarks, web history,
 * email, clipboard, accounts/tokens, audio recording, and cookies.
 * Also preserves GSF ID spoofing (moved from ContentResolver class hook).
 */
export namespace PIIWatcher {
  const NAME = "[PIIWatcher]"

  // ─── State ───────────────────────────────────────────────────────────

  let accessLog: AccessEntry[] = []

  // ─── URI Classification ──────────────────────────────────────────────

  const PII_URI_PATTERNS: Array<{ pattern: string; category: string }> = [
    { pattern: "content://com.android.contacts", category: "CONTACTS" },
    { pattern: "content://contacts", category: "CONTACTS" },
    { pattern: "content://call_log", category: "CALL_LOGS" },
    { pattern: "content://sms", category: "SMS_MMS" },
    { pattern: "content://mms-sms", category: "SMS_MMS" },
    { pattern: "content://mms", category: "SMS_MMS" },
    { pattern: "content://com.android.calendar", category: "CALENDAR" },
    { pattern: "content://media", category: "MEDIA_FILES" },
    { pattern: "content://browser/bookmarks", category: "BROWSER_BOOKMARKS" },
    { pattern: "content://browser/searches", category: "WEB_HISTORY" },
    { pattern: "content://com.android.browser", category: "WEB_HISTORY" },
    { pattern: "content://com.android.email", category: "EMAIL" },
    { pattern: "content://com.google.android.gm", category: "EMAIL" },
    { pattern: "content://user_dictionary", category: "USER_DICTIONARY" },
  ]

  const IGNORED_URI_PREFIXES = [
    "content://settings",
    "content://com.google.android.gsf",
    "content://com.android.providers.downloads",
    "content://com.google.android.apps.gsa",
  ]

  // ─── Public ──────────────────────────────────────────────────────────

  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m PII Watcher \x1b[0m` +
        `\n║ ├── ContentResolver: query/insert/update/delete (URI classification)` +
        `\n║ ├── Clipboard: ClipboardManager` +
        `\n║ ├── Accounts: AccountManager (accounts, tokens, passwords)` +
        `\n║ ├── Audio: MediaRecorder, AudioRecord` +
        `\n║ ├── Cookies: CookieManager` +
        `\n║ └── Spoofing: GSF ID (via ContentResolver.query)` +
        `\n╙────────────────────────────────────────────┘`,
    )
  }

  export function perform(): void {
    info()
    try {
      hookContentResolver()
      hookClipboard()
      hookAccountManager()
      hookMediaRecorder()
      hookAudioRecord()
      hookCookieManager()
    } catch (error) {
      log(LogType.Error, NAME, `PII hooks failed: \n${error}`)
    }
  }

  export function getAccessLog(): AccessEntry[] {
    return accessLog
  }

  // ─── Hooks ───────────────────────────────────────────────────────────

  function hookContentResolver(): void {
    try {
      const CR = Java.use("android.content.ContentResolver")
      const MatrixCursor = Java.use("android.database.MatrixCursor")
      const device = getActiveProfile().device

      // Hook query (all overloads)
      CR.query.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const uri = args[0] ? args[0].toString() : ""
          const result = this.query(...args)

          // GSF ID spoofing
          try {
            if (uri === "content://com.google.android.gsf.gservices" && args[3] === "android_id") {
              const gsfidHex = device.GSF_ID
              const gsfidDec = BigInt("0x" + gsfidHex)
              const strArray = Java.array("java.lang.String", ["key", "value"])
              const objArray = Java.array("Ljava.lang.Object;", ["android_id", gsfidDec.toString()])
              const customCursor = MatrixCursor.$new(strArray)
              customCursor.addRow(objArray)
              log(
                LogType.Verbose,
                NAME,
                `ContentResolver.query: spoofed GSF ID to ${gsfidHex} (${gsfidDec})`,
              )
              return customCursor
            }
          } catch (_) {}

          // PII monitoring — classify URI
          const category = classifyUri(uri)
          if (category) {
            const stack = getStackTrace()
            const projection = args[1] ? String(args[1]) : "*"
            const selection = args[2] ? String(args[2]) : ""
            recordAccess(
              "ContentResolver.query",
              category,
              `uri=${uri}, projection=${projection}, selection=${selection}`,
              stack,
            )
          }

          return result
        }
      })

      // Hook insert (all overloads)
      CR.insert.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const uri = args[0] ? args[0].toString() : ""
          const category = classifyUri(uri)
          if (category) {
            const stack = getStackTrace()
            recordAccess("ContentResolver.insert", category, `uri=${uri}`, stack)
          }
          return this.insert(...args)
        }
      })

      // Hook update (all overloads)
      CR.update.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const uri = args[0] ? args[0].toString() : ""
          const category = classifyUri(uri)
          if (category) {
            const stack = getStackTrace()
            const selection = args[2] ? String(args[2]) : ""
            recordAccess(
              "ContentResolver.update",
              category,
              `uri=${uri}, selection=${selection}`,
              stack,
            )
          }
          return this.update(...args)
        }
      })

      // Hook delete (all overloads)
      CR.delete.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          const uri = args[0] ? args[0].toString() : ""
          const category = classifyUri(uri)
          if (category) {
            const stack = getStackTrace()
            const selection = args[1] ? String(args[1]) : ""
            recordAccess(
              "ContentResolver.delete",
              category,
              `uri=${uri}, selection=${selection}`,
              stack,
            )
          }
          return this.delete(...args)
        }
      })

      log(LogType.Hook, NAME, `ContentResolver PII monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `ContentResolver hooks failed: ${error}`)
    }
  }

  function hookClipboard(): void {
    try {
      const ClipboardManager = Java.use("android.content.ClipboardManager")

      try {
        ClipboardManager.getPrimaryClip.implementation = function () {
          const result = this.getPrimaryClip()
          const stack = getStackTrace()
          let clipText = ""
          try {
            if (result !== null && result.getItemCount() > 0) {
              clipText = result.getItemAt(0).getText()
              if (clipText !== null) clipText = clipText.toString()
            }
          } catch (_) {}
          recordAccess(
            "ClipboardManager.getPrimaryClip",
            "CLIPBOARD",
            `text=${clipText || "[empty]"}`,
            stack,
          )
          return result
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getPrimaryClip: ${e}`)
      }

      try {
        ClipboardManager.hasPrimaryClip.implementation = function () {
          const result = this.hasPrimaryClip()
          const stack = getStackTrace()
          recordAccess("ClipboardManager.hasPrimaryClip", "CLIPBOARD", `result=${result}`, stack)
          return result
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook hasPrimaryClip: ${e}`)
      }

      try {
        ClipboardManager.setPrimaryClip.implementation = function (...args: any) {
          const stack = getStackTrace()
          let clipText = ""
          try {
            const clip = args[0]
            if (clip !== null && clip.getItemCount() > 0) {
              clipText = clip.getItemAt(0).getText()
              if (clipText !== null) clipText = clipText.toString()
            }
          } catch (_) {}
          recordAccess(
            "ClipboardManager.setPrimaryClip",
            "CLIPBOARD",
            `text=${clipText || "[empty]"}`,
            stack,
          )
          return this.setPrimaryClip(...args)
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook setPrimaryClip: ${e}`)
      }

      log(LogType.Hook, NAME, `ClipboardManager PII monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `ClipboardManager hooks failed: ${error}`)
    }
  }

  function hookAccountManager(): void {
    try {
      const AccountManager = Java.use("android.accounts.AccountManager")

      try {
        AccountManager.getAccounts.implementation = function () {
          const result = this.getAccounts()
          const stack = getStackTrace()
          let accounts = "[]"
          try {
            const arr: string[] = []
            for (let i = 0; i < result.length; i++) {
              arr.push(`${result[i].type}:${result[i].name}`)
            }
            accounts = `[${arr.join(", ")}]`
          } catch (_) {}
          recordAccess("AccountManager.getAccounts", "ACCOUNTS", accounts, stack)
          return result
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getAccounts: ${e}`)
      }

      try {
        AccountManager.getAccountsByType.implementation = function (...args: any) {
          const result = this.getAccountsByType(...args)
          const stack = getStackTrace()
          const type = args[0] ? String(args[0]) : "*"
          let accounts = "[]"
          try {
            const arr: string[] = []
            for (let i = 0; i < result.length; i++) {
              arr.push(`${result[i].type}:${result[i].name}`)
            }
            accounts = `[${arr.join(", ")}]`
          } catch (_) {}
          recordAccess(
            "AccountManager.getAccountsByType",
            "ACCOUNTS",
            `type=${type}, accounts=${accounts}`,
            stack,
          )
          return result
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getAccountsByType: ${e}`)
      }

      try {
        AccountManager.getAuthToken.overloads.forEach((overload: any) => {
          overload.implementation = function (...args: any) {
            const stack = getStackTrace()
            let account = ""
            try {
              account = args[0] ? `${args[0].type}:${args[0].name}` : ""
            } catch (_) {}
            const authTokenType = args[1] ? String(args[1]) : ""
            recordAccess(
              "AccountManager.getAuthToken",
              "OAUTH_TOKEN",
              `account=${account}, tokenType=${authTokenType}`,
              stack,
            )
            return this.getAuthToken(...args)
          }
        })
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getAuthToken: ${e}`)
      }

      try {
        AccountManager.peekAuthToken.implementation = function (...args: any) {
          const result = this.peekAuthToken(...args)
          const stack = getStackTrace()
          let account = ""
          try {
            account = args[0] ? `${args[0].type}:${args[0].name}` : ""
          } catch (_) {}
          const authTokenType = args[1] ? String(args[1]) : ""
          recordAccess(
            "AccountManager.peekAuthToken",
            "OAUTH_TOKEN",
            `account=${account}, tokenType=${authTokenType}, hasToken=${result !== null}`,
            stack,
          )
          return result
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook peekAuthToken: ${e}`)
      }

      try {
        AccountManager.getPassword.implementation = function (...args: any) {
          const result = this.getPassword(...args)
          const stack = getStackTrace()
          let account = ""
          try {
            account = args[0] ? `${args[0].type}:${args[0].name}` : ""
          } catch (_) {}
          recordAccess("AccountManager.getPassword", "PASSWORD", `account=${account}`, stack)
          return result
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook getPassword: ${e}`)
      }

      log(LogType.Hook, NAME, `AccountManager PII monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `AccountManager hooks failed: ${error}`)
    }
  }

  function hookMediaRecorder(): void {
    try {
      const MediaRecorder = Java.use("android.media.MediaRecorder")

      try {
        MediaRecorder.setAudioSource.implementation = function (...args: any) {
          const stack = getStackTrace()
          const source = args[0] !== undefined ? String(args[0]) : "unknown"
          recordAccess("MediaRecorder.setAudioSource", "AUDIO_RECORDING", `source=${source}`, stack)
          return this.setAudioSource(...args)
        }
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook MediaRecorder.setAudioSource: ${e}`)
      }

      log(LogType.Hook, NAME, `MediaRecorder PII monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `MediaRecorder hooks failed: ${error}`)
    }
  }

  function hookAudioRecord(): void {
    try {
      const AudioRecord = Java.use("android.media.AudioRecord")

      try {
        AudioRecord.startRecording.overloads.forEach((overload: any) => {
          overload.implementation = function (...args: any) {
            const stack = getStackTrace()
            recordAccess(
              "AudioRecord.startRecording",
              "AUDIO_RECORDING",
              `state=${this.getState()}`,
              stack,
            )
            return this.startRecording(...args)
          }
        })
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook AudioRecord.startRecording: ${e}`)
      }

      log(LogType.Hook, NAME, `AudioRecord PII monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `AudioRecord hooks failed: ${error}`)
    }
  }

  function hookCookieManager(): void {
    try {
      const CookieManager = Java.use("android.webkit.CookieManager")

      try {
        CookieManager.getCookie.overloads.forEach((overload: any) => {
          overload.implementation = function (...args: any) {
            const result = this.getCookie(...args)
            const stack = getStackTrace()
            const url = args[0] ? String(args[0]) : ""
            recordAccess(
              "CookieManager.getCookie",
              "COOKIE",
              `url=${url}, hasCookie=${result !== null}`,
              stack,
            )
            return result
          }
        })
      } catch (e) {
        log(LogType.Debug, NAME, `Could not hook CookieManager.getCookie: ${e}`)
      }

      log(LogType.Hook, NAME, `CookieManager PII monitoring hooked`)
    } catch (error) {
      log(LogType.Debug, NAME, `CookieManager hooks failed: ${error}`)
    }
  }

  // ─── Utilities ───────────────────────────────────────────────────────

  function classifyUri(uri: string): string | null {
    if (!uri || !uri.startsWith("content://")) return null

    // Skip ignored (noisy, non-PII) URIs
    for (const prefix of IGNORED_URI_PREFIXES) {
      if (uri.startsWith(prefix)) return null
    }

    // Match known PII patterns
    for (const entry of PII_URI_PATTERNS) {
      if (uri.startsWith(entry.pattern)) return entry.category
    }

    // Any other content:// URI is potential cross-app data access
    return "OTHER_APP_DATA"
  }

  function recordAccess(api: string, category: string, value: string, stack: string): void {
    accessLog.push({ timestamp: Date.now(), api, category, value, stack })
    log(LogType.Hook, NAME, `[${category}] ${api}: ${value}${formatStackLog(stack)}`)
  }
}
