import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.net.InetAddress class to spoof internet addresses.
 */
export namespace JavaNetInetAddress {
    const NAME = "[InetAddress]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const InetAddress = Java.use("java.net.InetAddress");

            // Hook getHostAddress to return spoofed public IP
            InetAddress.getHostAddress.implementation = function () {
                const ret = this.getHostAddress();
                // Only spoof external addresses, keep local ones
                if (ret !== "127.0.0.1" && !ret.startsWith("192.168.") && !ret.startsWith("10.") && !ret.startsWith("172.")) {
                    log(`InetAddress.getHostAddress: ${ret} -> 8.8.8.8`);
                    return "8.8.8.8";
                }
                return ret;
            };

            // Hook getHostName to return spoofed hostname for external addresses
            InetAddress.getHostName.implementation = function () {
                const ret = this.getHostName();
                const address = this.getHostAddress();
                // Only spoof external addresses, keep local ones
                if (address !== "127.0.0.1" && !address.startsWith("192.168.") && !address.startsWith("10.") && !address.startsWith("172.")) {
                    log(`InetAddress.getHostName: ${ret} -> dns.google`);
                    return "dns.google";
                }
                return ret;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}