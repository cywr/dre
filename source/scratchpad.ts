import * as Utils from "./utils/functions"
import { Logger } from "./utils/logger";
import Java from "frida-java-bridge";

/**
 * Scratchpad namespace for testing experimental hooks.
 */
export namespace Scratchpad {
    const NAME = "[Scratchpad]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function performNow(): void {
        info()
        try {
            scratch();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`);
        }
    }

    function info(): void {
        Logger.log(
            Logger.Type.Debug,
            NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └──\x1b[35m ? \x1b[0m`
            + `\n╟─┬\x1b[31m Native Files \x1b[0m`
            + `\n║ └──\x1b[35m ? \x1b[0m`
        + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    function scratch() {
        // Add experimental hooks here
    }
}