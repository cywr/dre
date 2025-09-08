import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.widget.TextView class to control text view operations and resource usage.
 */
export namespace AndroidWidgetTextView {
    const NAME = "[TextView]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            cutResources();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Control text view methods to manage resource usage.
     */
    function cutResources(): void {
        try {
            const TextView = Java.use("android.widget.TextView");
            
            TextView.setTypeface.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    log(`setTypeface blocked`);
                    return;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `cutResources failed: ${error}`);
        }
    }
}