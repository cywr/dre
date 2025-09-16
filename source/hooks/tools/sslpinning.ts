import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Unified SSL pinning bypass hook that combines multiple SSL/TLS certificate validation bypasses.
 */
export namespace SSLPinning {
    const NAME = "[SSLPinning]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    /**
     * Logs general information about the SSL pinning bypass hook.
     */
    export function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m SSL Pinning Bypass Suite \x1b[0m`
            + `\n║ ├── SSLContext Custom TrustManager`
            + `\n║ ├── X509TrustManager Bypass`
            + `\n║ └── Android TrustManagerImpl Bypass`
            + `\n╙──────────────────────────────────────────────────────┘`
        );
    }

    /**
     * Main hook method that enables comprehensive SSL pinning bypass.
     */
    export function perform(): void {
        info();
        
        try {
            bypassSSLContext();
            bypassX509TrustManager();
            bypassTrustManagerImpl();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Bypass SSL certificate validation by replacing TrustManagers in SSLContext.
     */
    function bypassSSLContext(): void {
        try {
            const SSLContext = Java.use("javax.net.ssl.SSLContext");
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

            const CustomTrustManager = Java.registerClass({
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
                    const customTrustManager = CustomTrustManager.$new();
                    return this.init(keyManagers, [customTrustManager], secureRandom);
                };
            });
            
            log(`SSLContext bypass enabled`);
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `SSLContext bypass failed: ${error}`);
        }
    }

    /**
     * Bypass X509TrustManager certificate validation methods.
     */
    function bypassX509TrustManager(): void {
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

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
            
            log(`X509TrustManager bypass enabled`);
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `X509TrustManager bypass failed: ${error}`);
        }
    }

    /**
     * Bypass Android's internal TrustManagerImpl certificate validation.
     */
    function bypassTrustManagerImpl(): void {
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
            
            log(`TrustManagerImpl bypass enabled`);
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `TrustManagerImpl bypass failed: ${error}`);
        }
    }
}