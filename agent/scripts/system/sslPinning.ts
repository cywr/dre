import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Perform hooks to bypass SSL/TLS certificate pinning validations.
 */
export namespace SSLPinning {
    const NAME = "[SSL Pinning]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function performNow(): void {
        info();
        try {
            sslContextBypass();
            trustManagerBypass();
            conscryptTrustManagerBypass();
            okHttpPinningBypass();
            legacyOkHttpPinningBypass();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`);
        }
    }

    function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m javax.net.ssl.SSLContext \x1b[0m`
            + `\n║ │ └── init`
            + `\n║ ├─┬\x1b[35m javax.net.ssl.X509TrustManager \x1b[0m`
            + `\n║ │ ├── checkClientTrusted`
            + `\n║ │ ├── checkServerTrusted`
            + `\n║ │ └── getAcceptedIssuers`
            + `\n║ ├─┬\x1b[35m com.android.org.conscrypt.TrustManagerImpl \x1b[0m`
            + `\n║ │ ├── checkServerTrusted`
            + `\n║ │ └── checkTrustedRecursive`
            + `\n║ ├─┬\x1b[35m okhttp3.CertificatePinner \x1b[0m`
            + `\n║ │ └── check`
            + `\n║ └─┬\x1b[35m com.android.okhttp.CertificatePinner \x1b[0m`
            + `\n║   └── check`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    /**
     * Bypasses SSL pinning by replacing SSLContext initialization with custom TrustManager.
     */
    function sslContextBypass() {
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

        try {
            const TrustManager = Java.registerClass({
                name: "com.generated.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain: any, authType: any) {
                        log(`Custom TrustManager: checkClientTrusted bypassed`);
                    },
                    checkServerTrusted: function(chain: any, authType: any) {
                        log(`Custom TrustManager: checkServerTrusted bypassed`);
                    },
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });

            SSLContext.init.overloads.forEach((overload: any) => {
                overload.implementation = function(keyManagers: any, trustManagers: any, secureRandom: any) {
                    log(`SSLContext.init: replacing TrustManagers with custom bypass`);
                    const customTrustManager = TrustManager.$new();
                    return this.init(keyManagers, [customTrustManager], secureRandom);
                };
            });
        } catch (error) {
            log(`SSLContext bypass failed: ${error}`);
        }
    }

    /**
     * Bypasses X509TrustManager certificate validation.
     */
    function trustManagerBypass() {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

        try {
            X509TrustManager.checkClientTrusted.implementation = function(chain: any, authType: any) {
                log(`X509TrustManager.checkClientTrusted: bypassed`);
            };

            X509TrustManager.checkServerTrusted.implementation = function(chain: any, authType: any) {
                log(`X509TrustManager.checkServerTrusted: bypassed`);
            };

            X509TrustManager.getAcceptedIssuers.implementation = function() {
                log(`X509TrustManager.getAcceptedIssuers: returning empty array`);
                return [];
            };
        } catch (error) {
            log(`X509TrustManager bypass failed: ${error}`);
        }
    }

    /**
     * Bypasses Android's internal TrustManagerImpl.
     */
    function conscryptTrustManagerBypass() {
        try {
            const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

            TrustManagerImpl.checkTrustedRecursive.implementation = function(
                certs: any, host: any, clientAuth: any, ocspData: any, tlsSctData: any
            ) {
                log(`TrustManagerImpl.checkTrustedRecursive: bypassed for ${host}`);
                return Java.use("java.util.ArrayList").$new();
            };

            TrustManagerImpl.checkServerTrusted.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    log(`TrustManagerImpl.checkServerTrusted: bypassed`);
                    return Java.use("java.util.ArrayList").$new();
                };
            });
        } catch (error) {
            log(`TrustManagerImpl bypass failed: ${error}`);
        }
    }

    /**
     * Bypasses OkHttp 3.x certificate pinning.
     */
    function okHttpPinningBypass() {
        try {
            const CertificatePinner = Java.use("okhttp3.CertificatePinner");

            CertificatePinner.check.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    log(`okhttp3.CertificatePinner.check: bypassed for ${args[0]}`);
                };
            });
        } catch (error) {
            log(`OkHttp3 CertificatePinner bypass failed: ${error}`);
        }
    }

    /**
     * Bypasses legacy OkHttp 2.x certificate pinning.
     */
    function legacyOkHttpPinningBypass() {
        try {
            const CertificatePinner = Java.use("com.android.okhttp.CertificatePinner");

            CertificatePinner.check.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    log(`com.android.okhttp.CertificatePinner.check: bypassed for ${args[0]}`);
                };
            });
        } catch (error) {
            log(`Legacy OkHttp CertificatePinner bypass failed: ${error}`);
        }
    }
}