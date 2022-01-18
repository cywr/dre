import { Logger } from "../utils/logger";
import * as Utils from "../utils/functions"

export namespace Scratchpad {
    const NAME = "[Scratchpad]";

    export function hook() {
        Logger.log(Logger.Type.Config, NAME, "Hooks loaded.");
        try {
            testing();
        } catch(error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed.\n${error}`);
        }
    }

    function testing() {
        
    }
}