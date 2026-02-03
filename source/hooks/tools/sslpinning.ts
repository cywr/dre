import { log, LogType } from "../../utils/logger"
import { Native } from "./native"
import Java from "frida-java-bridge"

/**
 * Unified SSL pinning bypass hook that combines multiple SSL/TLS certificate validation bypasses.
 * Covers standard Android, OkHttp, WebView, Flutter, Unity, Cocos2d, and generic BoringSSL/OpenSSL.
 */
export namespace SSLPinning {
  const NAME = "[SSLPinning]"

  /**
   * Logs general information about the SSL pinning bypass hook.
   */
  export function info(): void {
    log(
      LogType.Debug,
      NAME,
      `LogType: Hook` +
        `\n╓─┬\x1b[31m SSL Pinning Bypass Suite \x1b[0m` +
        `\n║ ├── Java: SSLContext, TrustManagerImpl, HostnameVerifier` +
        `\n║ ├── Java: OkHttp3, OkHttp, WebView, Trustkit` +
        `\n║ ├── Native: Flutter (BoringSSL), Generic BoringSSL/OpenSSL` +
        `\n║ └── Coverage: Standard, React Native, Flutter, Unity, Cocos` +
        `\n╙──────────────────────────────────────────────────────────────┘`,
    )
  }

  /**
   * Main hook method that enables comprehensive SSL pinning bypass.
   */
  export function perform(): void {
    info()

    // Java-layer bypasses (standard Android SSL stack)
    bypassSSLContext()
    bypassTrustManagerImpl()
    bypassHostnameVerifier()
    bypassOkHttp3()
    bypassOkHttpLegacy()
    bypassWebViewClient()
    bypassTrustkit()

    // Native-layer bypasses (hybrid/game frameworks)
    bypassFlutterSSL()
    bypassBoringSSL()
  }

  // ─── Java Standard ──────────────────────────────────────────────────

  /**
   * Bypass SSL certificate validation by replacing TrustManagers in SSLContext.
   */
  function bypassSSLContext(): void {
    try {
      const SSLContext = Java.use("javax.net.ssl.SSLContext")
      const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager")

      const CustomTrustManager = Java.registerClass({
        name: "com.generated.TrustManager",
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function (chain: any, authType: any) {
            log(LogType.Hook, NAME, `Custom TrustManager: checkClientTrusted bypassed`)
          },
          checkServerTrusted: function (chain: any, authType: any) {
            log(LogType.Hook, NAME, `Custom TrustManager: checkServerTrusted bypassed`)
          },
          getAcceptedIssuers: function () {
            return []
          },
        },
      })

      SSLContext.init.overloads.forEach((overload: any) => {
        overload.implementation = function (
          keyManagers: any,
          trustManagers: any,
          secureRandom: any,
        ) {
          log(LogType.Hook, NAME, `SSLContext.init: replacing TrustManagers with custom bypass`)
          const customTrustManager = CustomTrustManager.$new()
          return this.init(keyManagers, [customTrustManager], secureRandom)
        }
      })

      log(LogType.Hook, NAME, `SSLContext bypass enabled`)
    } catch (error) {
      log(LogType.Error, NAME, `SSLContext bypass failed: ${error}`)
    }
  }

  /**
   * Bypass Android's internal TrustManagerImpl certificate validation.
   */
  function bypassTrustManagerImpl(): void {
    try {
      const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl")

      TrustManagerImpl.checkTrustedRecursive.implementation = function (
        certs: any,
        host: any,
        clientAuth: any,
        ocspData: any,
        tlsSctData: any,
      ) {
        log(LogType.Hook, NAME, `TrustManagerImpl.checkTrustedRecursive: bypassed for ${host}`)
        return Java.use("java.util.ArrayList").$new()
      }

      TrustManagerImpl.checkServerTrusted.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          log(LogType.Hook, NAME, `TrustManagerImpl.checkServerTrusted: bypassed`)
          return Java.use("java.util.ArrayList").$new()
        }
      })

      log(LogType.Hook, NAME, `TrustManagerImpl bypass enabled`)
    } catch (error) {
      log(LogType.Error, NAME, `TrustManagerImpl bypass failed: ${error}`)
    }
  }

  /**
   * Bypass hostname verification on HttpsURLConnection.
   */
  function bypassHostnameVerifier(): void {
    try {
      const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection")
      const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier")

      const PermissiveVerifier = Java.registerClass({
        name: "com.generated.PermissiveHostnameVerifier",
        implements: [HostnameVerifier],
        methods: {
          verify: function (hostname: any, session: any) {
            log(LogType.Hook, NAME, `PermissiveHostnameVerifier: allowing ${hostname}`)
            return true
          },
        },
      })

      const permissiveVerifier = PermissiveVerifier.$new()

      HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier: any) {
        log(
          LogType.Hook,
          NAME,
          `HttpsURLConnection.setDefaultHostnameVerifier: replacing with permissive verifier`,
        )
        this.setDefaultHostnameVerifier(permissiveVerifier)
      }

      HttpsURLConnection.setHostnameVerifier.implementation = function (verifier: any) {
        log(
          LogType.Hook,
          NAME,
          `HttpsURLConnection.setHostnameVerifier: replacing with permissive verifier`,
        )
        this.setHostnameVerifier(permissiveVerifier)
      }

      HttpsURLConnection.setSSLSocketFactory.implementation = function (factory: any) {
        log(LogType.Hook, NAME, `HttpsURLConnection.setSSLSocketFactory: intercepted`)
        // Create a bypass SSLSocketFactory from our permissive SSLContext
        try {
          const SSLContext = Java.use("javax.net.ssl.SSLContext")
          const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager")

          const trustManager = Java.registerClass({
            name: "com.generated.SocketFactoryTrustManager",
            implements: [X509TrustManager],
            methods: {
              checkClientTrusted: function () {},
              checkServerTrusted: function () {},
              getAcceptedIssuers: function () {
                return []
              },
            },
          }).$new()

          const ctx = SSLContext.getInstance("TLS")
          ctx.init(null, [trustManager], null)
          this.setSSLSocketFactory(ctx.getSocketFactory())
        } catch (e) {
          // Fall back to original factory if we can't create bypass
          this.setSSLSocketFactory(factory)
        }
      }

      log(LogType.Hook, NAME, `HostnameVerifier bypass enabled`)
    } catch (error) {
      log(LogType.Error, NAME, `HostnameVerifier bypass failed: ${error}`)
    }
  }

  // ─── Java Libraries ─────────────────────────────────────────────────

  /**
   * Bypass OkHttp3 CertificatePinner (com.squareup.okhttp3).
   * Uses classloader enumeration to find OkHttp in non-default classloaders.
   */
  function bypassOkHttp3(): void {
    try {
      let hooked = false

      // Try default classloader first
      try {
        hookOkHttp3Pinner(Java.classFactory)
        hooked = true
      } catch (e) {
        // Not in default classloader
      }

      // Enumerate classloaders for apps with multiple DEX files
      if (!hooked) {
        Java.enumerateClassLoaders({
          onMatch: function (loader) {
            if (hooked) return
            try {
              loader.loadClass("com.squareup.okhttp3.CertificatePinner")
              const factory = Java.ClassFactory.get(loader)
              hookOkHttp3Pinner(factory)
              hooked = true
              log(LogType.Hook, NAME, `OkHttp3 found in non-default classloader`)
            } catch (e) {
              // Not in this loader
            }
          },
          onComplete: function () {},
        })
      }

      if (!hooked) {
        log(LogType.Debug, NAME, `OkHttp3 not found (app may not use it)`)
      }
    } catch (error) {
      log(LogType.Error, NAME, `OkHttp3 bypass failed: ${error}`)
    }
  }

  /**
   * Hook OkHttp3 CertificatePinner methods using the provided ClassFactory.
   */
  function hookOkHttp3Pinner(factory: Java.ClassFactory): void {
    const CertificatePinner = factory.use("com.squareup.okhttp3.CertificatePinner")

    // Standard check method
    try {
      CertificatePinner.check.overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          log(LogType.Hook, NAME, `OkHttp3 CertificatePinner.check: bypassed for ${args[0]}`)
          return
        }
      })
    } catch (e) {
      // check method variant not available
    }

    // Kotlin-mangled name in newer OkHttp versions
    try {
      CertificatePinner["check$okhttp"].overloads.forEach((overload: any) => {
        overload.implementation = function (...args: any) {
          log(LogType.Hook, NAME, `OkHttp3 CertificatePinner.check$okhttp: bypassed for ${args[0]}`)
          return
        }
      })
    } catch (e) {
      // check$okhttp not present (older OkHttp version)
    }

    log(LogType.Hook, NAME, `OkHttp3 CertificatePinner bypass enabled`)
  }

  /**
   * Bypass legacy OkHttp CertificatePinner (com.squareup.okhttp).
   */
  function bypassOkHttpLegacy(): void {
    try {
      let hooked = false

      try {
        hookOkHttpLegacyPinner(Java.classFactory)
        hooked = true
      } catch (e) {
        // Not in default classloader
      }

      if (!hooked) {
        Java.enumerateClassLoaders({
          onMatch: function (loader) {
            if (hooked) return
            try {
              loader.loadClass("com.squareup.okhttp.CertificatePinner")
              const factory = Java.ClassFactory.get(loader)
              hookOkHttpLegacyPinner(factory)
              hooked = true
              log(LogType.Hook, NAME, `OkHttp legacy found in non-default classloader`)
            } catch (e) {
              // Not in this loader
            }
          },
          onComplete: function () {},
        })
      }

      if (!hooked) {
        log(LogType.Debug, NAME, `OkHttp legacy not found (app may not use it)`)
      }
    } catch (error) {
      log(LogType.Error, NAME, `OkHttp legacy bypass failed: ${error}`)
    }
  }

  /**
   * Hook legacy OkHttp CertificatePinner methods using the provided ClassFactory.
   */
  function hookOkHttpLegacyPinner(factory: Java.ClassFactory): void {
    const CertificatePinner = factory.use("com.squareup.okhttp.CertificatePinner")

    CertificatePinner.check.overloads.forEach((overload: any) => {
      overload.implementation = function (...args: any) {
        log(LogType.Hook, NAME, `OkHttp legacy CertificatePinner.check: bypassed for ${args[0]}`)
        return
      }
    })

    log(LogType.Hook, NAME, `OkHttp legacy CertificatePinner bypass enabled`)
  }

  /**
   * Bypass WebViewClient SSL error handling to allow self-signed certificates in WebViews.
   */
  function bypassWebViewClient(): void {
    try {
      const WebViewClient = Java.use("android.webkit.WebViewClient")

      WebViewClient.onReceivedSslError.implementation = function (
        view: any,
        handler: any,
        error: any,
      ) {
        log(LogType.Hook, NAME, `WebViewClient.onReceivedSslError: proceeding past SSL error`)
        handler.proceed()
      }

      log(LogType.Hook, NAME, `WebViewClient SSL bypass enabled`)
    } catch (error) {
      log(LogType.Error, NAME, `WebViewClient bypass failed: ${error}`)
    }
  }

  /**
   * Bypass Trustkit SSL pinning library.
   */
  function bypassTrustkit(): void {
    try {
      let found = false

      try {
        const OkHostnameVerifier = Java.use(
          "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
        )
        OkHostnameVerifier.verify.overloads.forEach((overload: any) => {
          overload.implementation = function (...args: any) {
            log(LogType.Hook, NAME, `Trustkit OkHostnameVerifier.verify: bypassed`)
            return true
          }
        })
        found = true
      } catch (e) {
        // Trustkit OkHostnameVerifier not present
      }

      try {
        const PinningTrustManager = Java.use(
          "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
        )
        PinningTrustManager.checkServerTrusted.overloads.forEach((overload: any) => {
          overload.implementation = function (...args: any) {
            log(LogType.Hook, NAME, `Trustkit PinningTrustManager.checkServerTrusted: bypassed`)
          }
        })
        found = true
      } catch (e) {
        // Trustkit PinningTrustManager not present
      }

      if (found) {
        log(LogType.Hook, NAME, `Trustkit bypass enabled`)
      } else {
        log(LogType.Debug, NAME, `Trustkit not found (app may not use it)`)
      }
    } catch (error) {
      log(LogType.Error, NAME, `Trustkit bypass failed: ${error}`)
    }
  }

  // ─── Native Frameworks ──────────────────────────────────────────────

  /**
   * Bypass Flutter's bundled BoringSSL certificate verification in libflutter.so.
   * Uses export lookup first, then falls back to pattern scanning for stripped binaries.
   */
  function bypassFlutterSSL(): void {
    try {
      Native.waitLibrary(
        "libflutter.so",
        () => {
          try {
            const module = Process.getModuleByName("libflutter.so")
            log(LogType.Hook, NAME, `Flutter library found at ${module.base}, size: ${module.size}`)

            let targetAddr: NativePointer | null = null

            // Try exported symbol first
            try {
              targetAddr = module.findExportByName("ssl_crypto_x509_session_verify_cert_chain")
            } catch (e) {
              // Symbol not exported
            }

            // Fall back to pattern scanning for stripped binaries
            if (!targetAddr) {
              targetAddr = scanFlutterCertVerify(module)
            }

            if (targetAddr) {
              log(LogType.Hook, NAME, `Flutter cert verify function found at ${targetAddr}`)

              Interceptor.replace(
                targetAddr,
                new NativeCallback(
                  function () {
                    log(LogType.Hook, NAME, `Flutter SSL cert verification: bypassed`)
                    return 0x1 // Return 1 = valid
                  },
                  "int",
                  ["pointer", "pointer"],
                ),
              )

              log(LogType.Hook, NAME, `Flutter SSL bypass enabled`)
            } else {
              log(
                LogType.Error,
                NAME,
                `Flutter cert verify function not found (export or pattern scan)`,
              )
            }
          } catch (error) {
            log(LogType.Error, NAME, `Flutter SSL bypass hook failed: ${error}`)
          }
        },
        2000,
        15,
      ).catch((error) => {
        log(LogType.Debug, NAME, `Flutter library not loaded (app may not use Flutter): ${error}`)
      })
    } catch (error) {
      log(LogType.Error, NAME, `Flutter SSL bypass failed: ${error}`)
    }
  }

  /**
   * Scan libflutter.so for the cert verification function using known byte patterns.
   * Used when the binary is stripped and symbols are not exported.
   */
  function scanFlutterCertVerify(module: Module): NativePointer | null {
    let found: NativePointer | null = null

    // ARM64 pattern for ssl_crypto_x509_session_verify_cert_chain prologue
    const arm64Patterns = [
      "FF 83 01 D1 FD 7B 07 A9 F6 57 08 A9 F4 4F 09 A9",
      "FF 43 01 D1 FD 7B 04 A9 F4 4F 05 A9 F6 57 06 A9",
    ]

    // ARM32 pattern
    const arm32Patterns = ["F0 B5 03 AF 2D E9 00 0D"]

    const arch = Process.arch
    const patterns = arch === "arm64" ? arm64Patterns : arm32Patterns

    for (const pattern of patterns) {
      if (found) break

      try {
        Memory.scan(module.base, module.size, pattern, {
          onMatch: function (address, size) {
            if (!found) {
              found = address
              log(
                LogType.Hook,
                NAME,
                `Flutter pattern match at ${address} (pattern: ${pattern.substring(0, 20)}...)`,
              )
            }
          },
          onError: function (reason) {
            log(LogType.Error, NAME, `Flutter pattern scan error: ${reason}`)
          },
          onComplete: function () {},
        })
      } catch (e) {
        // Pattern scan failed for this pattern, try next
      }
    }

    return found
  }

  /**
   * Generic BoringSSL/OpenSSL bypass for any native library.
   * Covers Unity, Cocos2d, Xamarin, and other frameworks that bundle their own SSL.
   */
  function bypassBoringSSL(): void {
    try {
      const targetExports = ["SSL_CTX_set_custom_verify", "SSL_set_custom_verify"]

      const modules = Process.enumerateModules()

      for (const mod of modules) {
        for (const exportName of targetExports) {
          try {
            const addr = mod.findExportByName(exportName)
            if (addr) {
              hookBoringSSLVerify(mod.name, exportName, addr)
            }
          } catch (e) {
            // Export not in this module
          }
        }
      }
    } catch (error) {
      log(LogType.Error, NAME, `BoringSSL bypass failed: ${error}`)
    }
  }

  /**
   * Hook a BoringSSL/OpenSSL verify function to replace the callback with a no-op.
   * ssl_verify_ok = 0 in BoringSSL.
   */
  function hookBoringSSLVerify(moduleName: string, exportName: string, addr: NativePointer): void {
    try {
      // SSL_CTX_set_custom_verify(SSL_CTX *ctx, int mode, enum ssl_verify_result_t (*callback)(...))
      // SSL_set_custom_verify(SSL *ssl, int mode, enum ssl_verify_result_t (*callback)(...))
      // We intercept the call and replace the callback argument with one that returns ssl_verify_ok (0)
      const noOpVerifyCallback = new NativeCallback(
        function () {
          log(
            LogType.Hook,
            NAME,
            `BoringSSL verify callback (${moduleName}): returning ssl_verify_ok`,
          )
          return 0 // ssl_verify_ok
        },
        "int",
        ["pointer", "pointer"],
      )

      Interceptor.attach(addr, {
        onEnter: function (args) {
          log(LogType.Hook, NAME, `${moduleName}::${exportName}: replacing verify callback`)
          args[2] = noOpVerifyCallback
        },
      })

      log(LogType.Hook, NAME, `BoringSSL bypass enabled for ${moduleName}::${exportName}`)
    } catch (error) {
      log(LogType.Error, NAME, `BoringSSL hook failed for ${moduleName}::${exportName}: ${error}`)
    }
  }
}
