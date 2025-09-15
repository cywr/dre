import { Logger } from "./utils/logger";
import * as Utils from "./utils/functions"
import Java from "frida-java-bridge";
import { Native } from "./hooks/tools/native";

/**
 * Scratchpad namespace for testing experimental hooks.
 */
export namespace Scratchpad {
    const NAME = "[Scratchpad]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function perform(): void {
    
    }
}