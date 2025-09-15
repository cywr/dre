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

            // Check if getUserAgentString method exists before hooking
            if (WebView.getUserAgentString) {
                WebView.getUserAgentString.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        const ret = this.getUserAgentString(...args);
                        if (ret.includes("Android SDK built for x86") || ret.includes("Emulator") || ret.includes("generic")) {
                            const spoofedUA = "Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36";
                            log(`WebView.getUserAgentString: spoofed emulator UA`);
                            return spoofedUA;
                        }
                        return ret;
                    };
                });
                log("WebView.getUserAgentString overloads hooked successfully");
            } else {
                log("getUserAgentString method not found in WebView, skipping hook");
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}