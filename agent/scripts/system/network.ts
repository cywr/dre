import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on network-related classes to bypass anti-emulation validations.
 */
export class Network extends Hook {
    NAME = "[Network]";
    LOG_TYPE = Logger.Type.Hook;

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ ├─┬\x1b[35m android.net.ConnectivityManager \x1b[0m`
            + `\n║ │ └── getMobileDataEnabled`
            + `\n║ ├─┬\x1b[35m android.net.NetworkInfo \x1b[0m`
            + `\n║ │ ├── getType`
            + `\n║ │ ├── getTypeName`
            + `\n║ │ └── getSubtype`
            + `\n║ ├─┬\x1b[35m android.net.wifi.WifiInfo \x1b[0m`
            + `\n║ │ ├── getSSID`
            + `\n║ │ ├── getBSSID`
            + `\n║ │ └── getMacAddress`
            + `\n║ └─┬\x1b[35m java.net.InetAddress \x1b[0m`
            + `\n║   ├── getHostAddress`
            + `\n║   └── getHostName`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info();
        try {
            this.connectivityManager();
            this.networkInfo();
            this.wifiInfo();
            this.inetAddress();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private ConnectivityManager = Java.use("android.net.ConnectivityManager");
    private NetworkInfo = Java.use("android.net.NetworkInfo");
    private WifiInfo = Java.use("android.net.wifi.WifiInfo");
    private InetAddress = Java.use("java.net.InetAddress");

    /**
     * Hooks ConnectivityManager to bypass mobile data detection.
     */
    connectivityManager() {
        const log = this.log;

        try {
            this.ConnectivityManager.getMobileDataEnabled.implementation = function() {
                const ret = this.getMobileDataEnabled();
                log(`ConnectivityManager.getMobileDataEnabled: ${ret} -> true`);
                return true;
            };
        } catch (error) {
            log(`ConnectivityManager hooks failed: ${error}`);
        }
    }

    /**
     * Hooks NetworkInfo to spoof network type information.
     */
    networkInfo() {
        const log = this.log;

        try {
            this.NetworkInfo.getType.implementation = function() {
                const ret = this.getType();
                // TYPE_MOBILE = 0, TYPE_WIFI = 1
                const spoofedType = 1; // Always return WiFi
                log(`NetworkInfo.getType: ${ret} -> ${spoofedType}`);
                return spoofedType;
            };

            this.NetworkInfo.getTypeName.implementation = function() {
                const ret = this.getTypeName();
                const spoofedTypeName = "WIFI";
                log(`NetworkInfo.getTypeName: ${ret} -> ${spoofedTypeName}`);
                return spoofedTypeName;
            };

            this.NetworkInfo.getSubtype.implementation = function() {
                const ret = this.getSubtype();
                // Return -1 for WiFi (no subtype)
                const spoofedSubtype = -1;
                log(`NetworkInfo.getSubtype: ${ret} -> ${spoofedSubtype}`);
                return spoofedSubtype;
            };
        } catch (error) {
            log(`NetworkInfo hooks failed: ${error}`);
        }
    }

    /**
     * Hooks WifiInfo to spoof WiFi network information.
     */
    wifiInfo() {
        const log = this.log;

        try {
            this.WifiInfo.getSSID.implementation = function() {
                const ret = this.getSSID();
                const spoofedSSID = '"AndroidWifi"';
                log(`WifiInfo.getSSID: ${ret} -> ${spoofedSSID}`);
                return spoofedSSID;
            };

            this.WifiInfo.getBSSID.implementation = function() {
                const ret = this.getBSSID();
                const spoofedBSSID = "02:00:00:00:00:00";
                log(`WifiInfo.getBSSID: ${ret} -> ${spoofedBSSID}`);
                return spoofedBSSID;
            };

            this.WifiInfo.getMacAddress.implementation = function() {
                const ret = this.getMacAddress();
                const spoofedMac = "02:00:00:00:00:00";
                log(`WifiInfo.getMacAddress: ${ret} -> ${spoofedMac}`);
                return spoofedMac;
            };
        } catch (error) {
            log(`WifiInfo hooks failed: ${error}`);
        }
    }

    /**
     * Hooks InetAddress to spoof network addresses.
     */
    inetAddress() {
        const log = this.log;

        try {
            this.InetAddress.getHostAddress.implementation = function() {
                const ret = this.getHostAddress();
                // Don't spoof localhost or private networks
                if (ret !== "127.0.0.1" && !ret.startsWith("192.168.") && !ret.startsWith("10.") && !ret.startsWith("172.")) {
                    const spoofedAddress = "8.8.8.8";
                    log(`InetAddress.getHostAddress: ${ret} -> ${spoofedAddress}`);
                    return spoofedAddress;
                }
                return ret;
            };

            this.InetAddress.getHostName.implementation = function() {
                const ret = this.getHostName();
                const address = this.getHostAddress();
                
                // Only spoof external addresses
                if (address !== "127.0.0.1" && !address.startsWith("192.168.") && !address.startsWith("10.") && !address.startsWith("172.")) {
                    const spoofedHostname = "dns.google";
                    log(`InetAddress.getHostName: ${ret} -> ${spoofedHostname}`);
                    return spoofedHostname;
                }
                return ret;
            };
        } catch (error) {
            log(`InetAddress hooks failed: ${error}`);
        }
    }
}