import * as Classes from './classes';
import { Logger } from "../../utils/logger";

/**
 * Aggregator for monitoring and analysis hooks.
 */
export namespace Monitoring {
    const NAME = "[Monitoring]";

    /**
     * Logs general information about the module.
     */
    export function info(): void {
        Logger.log(
            Logger.Type.Debug, 
            NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Monitoring Tools \x1b[0m`
            + `\n║ └── SharedPreferences Watcher`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    /**
     * Main hook method that enables all monitoring tools.
     * @param targets Optional list of specific SharedPreferences files to monitor
     */
    export function performNow(targets?: string[]): void {
        info();
        try {
            sharedPreferencesMonitoring();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: \n${error}`);
        }
    }

    /**
     * Enable SharedPreferences monitoring and analysis.
     */
    function sharedPreferencesMonitoring(): void {
        Classes.SharedPreferencesImpl.performNow();
        Classes.SharedPreferencesImplEditorImpl.performNow();
    }
}