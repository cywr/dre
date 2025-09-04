import * as Utils from "../utils/functions"
import { Logger } from "../utils/logger";
import { Hook } from "../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on the system to bypass anti-debug validations.
*/
export class Scratchpad extends Hook {
    NAME = "[Scratchpad]";
    LOG_TYPE = Logger.Type.Hook;

    info(): void {
        Logger.log(
            Logger.Type.Debug,
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └──\x1b[35m ? \x1b[0m`
            + `\n╟─┬\x1b[31m Native Files \x1b[0m`
            + `\n║ └──\x1b[35m ? \x1b[0m`
        + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    execute(): void {
        this.info()
        try {
            this.scratch();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    scratch() {

    }
}