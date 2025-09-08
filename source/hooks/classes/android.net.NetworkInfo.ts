import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.net.NetworkInfo class to spoof network information.
 */
export namespace NetworkInfo {
    const NAME = "[NetworkInfo]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const NetworkInfo = Java.use("android.net.NetworkInfo");

            // Hook getType to return WIFI connection type
            NetworkInfo.getType.implementation = function () {
                const ret = this.getType();
                log(`NetworkInfo.getType: ${ret} -> 1 (WIFI)`);
                return 1;
            };

            // Hook getTypeName to return WIFI
            NetworkInfo.getTypeName.implementation = function () {
                const ret = this.getTypeName();
                log(`NetworkInfo.getTypeName: ${ret} -> WIFI`);
                return "WIFI";
            };

            // Hook getSubtype to return -1 (no subtype for WiFi)
            NetworkInfo.getSubtype.implementation = function () {
                const ret = this.getSubtype();
                log(`NetworkInfo.getSubtype: ${ret} -> -1`);
                return -1;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}