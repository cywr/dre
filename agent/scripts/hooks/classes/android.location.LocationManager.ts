import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.location.LocationManager class to spoof location manager functionality.
 */
export namespace AndroidLocationLocationManager {
    const NAME = "[LocationManager]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const LocationManager = Java.use("android.location.LocationManager");

            // Hook isProviderEnabled to always return true for GPS and network providers
            LocationManager.isProviderEnabled.overload("java.lang.String").implementation = function (provider: string) {
                const ret = this.isProviderEnabled(provider);
                if (provider === "gps" || provider === "network") {
                    log(`LocationManager.isProviderEnabled: ${provider} -> true`);
                    return true;
                }
                return ret;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}