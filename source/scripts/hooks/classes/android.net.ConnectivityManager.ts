import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.net.ConnectivityManager class to spoof network connectivity information.
 */
export namespace ConnectivityManager {
    const NAME = "[ConnectivityManager]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const ConnectivityManager = Java.use("android.net.ConnectivityManager");

            // Hook getMobileDataEnabled to always return true
            ConnectivityManager.getMobileDataEnabled.implementation = function () {
                const ret = this.getMobileDataEnabled();
                log(`ConnectivityManager.getMobileDataEnabled: ${ret} -> true`);
                return true;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}