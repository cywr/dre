import * as ToolsIndex from './tools/index';
import { Logger } from "../utils/logger";

/**
 * Aggregator for development and analysis tools.
 */
export namespace DevTools {
    const NAME = "[Dev Tools]";

    /**
     * Logs general information about the module.
     */
    export function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Analysis Tools \x1b[0m`
            + `\n║ ├── Cipher Interception`
            + `\n║ └── Base64 Monitoring`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    /**
     * Main hook method that enables all development tools.
     */
    export function perform(): void {
        info();
        try {
            cryptographyTools();
            encodingTools();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`);
        }
    }

    /**
     * Enable cryptography analysis tools.
     */
    function cryptographyTools(): void {
        ToolsIndex.Cipher.perform();
    }

    /**
     * Enable encoding/decoding monitoring tools.
     */
    function encodingTools(): void {
        ToolsIndex.Base64.perform();
    }
}