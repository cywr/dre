import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for javax.net.ssl.X509TrustManager class to bypass certificate validation.
 */
export namespace X509TrustManager {
    const NAME = "[X509TrustManager]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function performNow(): void {
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
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}