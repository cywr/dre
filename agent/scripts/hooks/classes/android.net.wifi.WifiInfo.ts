import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.net.wifi.WifiInfo class to spoof WiFi information.
 */
export namespace AndroidNetWifiWifiInfo {
    const NAME = "[WifiInfo]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const WifiInfo = Java.use("android.net.wifi.WifiInfo");

            // Hook getSSID to return spoofed SSID
            WifiInfo.getSSID.implementation = function () {
                const ret = this.getSSID();
                log(`WifiInfo.getSSID: ${ret} -> "AndroidWifi"`);
                return '"AndroidWifi"';
            };

            // Hook getBSSID to return spoofed BSSID
            WifiInfo.getBSSID.implementation = function () {
                const ret = this.getBSSID();
                log(`WifiInfo.getBSSID: ${ret} -> 02:00:00:00:00:00`);
                return "02:00:00:00:00:00";
            };

            // Hook getMacAddress to return spoofed MAC address
            WifiInfo.getMacAddress.implementation = function () {
                const ret = this.getMacAddress();
                log(`WifiInfo.getMacAddress: ${ret} -> 02:00:00:00:00:00`);
                return "02:00:00:00:00:00";
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}