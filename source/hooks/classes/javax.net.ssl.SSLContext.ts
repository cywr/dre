import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for javax.net.ssl.SSLContext class to bypass SSL certificate validation.
 */
export namespace SSLContext {
    const NAME = "[SSLContext]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function perform(): void {
        try {
            const SSLContext = Java.use("javax.net.ssl.SSLContext");
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

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
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}