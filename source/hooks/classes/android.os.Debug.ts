import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.os.Debug class to bypass debug detection.
 */
export namespace Debug {
    const NAME = "[Debug]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            const DebugClass = Java.use('android.os.Debug');
            
            DebugClass.isDebuggerConnected.implementation = function () {
                log("Debug.isDebuggerConnected: false");
                return false;
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}