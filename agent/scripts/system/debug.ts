import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";

/**
 * Perform hooks on the system to bypass anti-debug validations.
*/
export class Debug implements Hook {
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
            this.checks(this)
        } catch(error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`)
        }
    }

    /** Hooked classes */
    _Debug = Java.use('android.os.Debug')

    checks(_this: Debug) {
        _this._Debug.isDebuggerConnected.implementation = function () {
            Logger.log(_this.LOG_TYPE, _this.NAME, "Debug.isDebuggerConnected: false");
            return false;
        }
    }
}
