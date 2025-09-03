import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on the system to bypass anti-debug validations.
*/
export class Debug extends Hook {
    NAME = "[Anti-Debug]"
    LOG_TYPE = Logger.Type.Debug
     
    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Debug`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └─┬\x1b[35m android.os.Debug \x1b[0m`
            + `\n║   └── isDebuggerConnected`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    execute(): void {
        this.info()
        try {
            this.checks()
        } catch(error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`)
        }
    }

    private Debug = Java.use('android.os.Debug')

    checks() {
        const log = this.log;
        
        this.Debug.isDebuggerConnected.implementation = function () {
            log("Debug.isDebuggerConnected: false");
            return false;
        }
    }
}
