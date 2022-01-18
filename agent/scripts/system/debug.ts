import { Logger } from "../../utils/logger";

export namespace Debug {
    const NAME = "[Anti-Debug]";
    /**
     * Perform hooks on the system to bypass anti-debug validations.
     * 
     */
    export function hook() {
        Logger.log(Logger.Type.Config, NAME, "Hooks loaded.");
        try {
            const Debug = Java.use('android.os.Debug')
            Debug.isDebuggerConnected.implementation = function () {
                Logger.log(Logger.Type.Hook, NAME, "Debug.isDebuggerConnected: false");
                return false;
            }
        } catch(error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed.\n${error}`);
        }
    }
}
