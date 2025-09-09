import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.net.InetAddress class to spoof internet address information.
 */
export namespace InetAddress {
    const NAME = "[InetAddress]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function perform(): void {
        try {
            const InetAddress = Java.use("java.net.InetAddress");

            // Hook getHostAddress to spoof external IP addresses
            InetAddress.getHostAddress.implementation = function () {
                const ret = this.getHostAddress();
                if (ret !== "127.0.0.1" && !ret.startsWith("192.168.") && !ret.startsWith("10.") && !ret.startsWith("172.")) {
                    log(`InetAddress.getHostAddress: ${ret} -> 8.8.8.8`);
                    return "8.8.8.8";
                }
                return ret;
            };

            // Hook getHostName to spoof external host names
            InetAddress.getHostName.implementation = function () {
                const ret = this.getHostName();
                const address = this.getHostAddress();
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