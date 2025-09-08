import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for com.android.org.conscrypt.TrustManagerImpl class to bypass Android's internal trust manager.
 */
export namespace TrustManagerImpl {
    const NAME = "[TrustManagerImpl]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function performNow(): void {
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
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}