import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.provider.Settings$Global class to spoof global settings.
 */
export namespace SettingsGlobal {
    const NAME = "[Settings.Global]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const SettingsGlobal = Java.use("android.provider.Settings$Global");

            SettingsGlobal.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, number: number) {
                const ret = this.getInt(cr, name, number);

                switch (name) {
                    case "development_settings_enabled":
                        log(`Settings.Global.getInt: ${name} -> 0`);
                        return 0;
                    case "airplane_mode_on":
                        log(`Settings.Global.getInt: ${name} -> 0`);
                        return 0;
                    case "mobile_data":
                        log(`Settings.Global.getInt: ${name} -> 1`);
                        return 1;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}