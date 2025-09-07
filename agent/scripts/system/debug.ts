import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Perform hooks on the system to bypass anti-debug validations.
 */
export namespace Debug {
    const NAME = "[Anti-Debug]"
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message)

    export function performNow(): void {
        info()
        try {
            checks()
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`)
        }
    }

    function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Debug`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └─┬\x1b[35m android.os.Debug \x1b[0m`
            + `\n║   └── isDebuggerConnected`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    function checks() {
        const DebugClass = Java.use('android.os.Debug')
        
        DebugClass.isDebuggerConnected.implementation = function () {
            log("Debug.isDebuggerConnected: false");
            return false;
        }
    }
}
