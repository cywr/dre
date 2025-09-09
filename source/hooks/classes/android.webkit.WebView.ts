import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.webkit.WebView class to spoof user agent strings.
 */
export namespace WebView {
    const NAME = "[WebView]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function perform(): void {
        try {
            const WebView = Java.use("android.webkit.WebView");

            // Hook getUserAgentString with context parameter
            WebView.getUserAgentString.overload("android.content.Context").implementation = function (context: any) {
                const ret = this.getUserAgentString(context);
                if (ret.includes("Android SDK built for x86") || ret.includes("Emulator") || ret.includes("generic")) {
                    const spoofedUA = "Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36";
                    log(`WebView.getUserAgentString: spoofed emulator UA`);
                    return spoofedUA;
                }
                return ret;
            };

            // Hook getUserAgentString without parameters
            WebView.getUserAgentString.overload().implementation = function () {
                const ret = this.getUserAgentString();
                if (ret.includes("Android SDK built for x86") || ret.includes("Emulator") || ret.includes("generic")) {
                    const spoofedUA = "Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36";
                    log(`WebView.getUserAgentString: spoofed emulator UA`);
                    return spoofedUA;
                }
                return ret;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}