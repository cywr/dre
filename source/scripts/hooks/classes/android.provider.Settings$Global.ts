import { Logger } from "../../../utils/logger";
import { DEFAULT_GLOBAL_SETTINGS } from "../../../utils/types";
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
                        log(`Settings.Global.getInt: ${name} -> ${DEFAULT_GLOBAL_SETTINGS.development_settings_enabled}`);
                        return DEFAULT_GLOBAL_SETTINGS.development_settings_enabled;
                    case "adb_enabled":
                        log(`Settings.Global.getInt: ${name} -> ${DEFAULT_GLOBAL_SETTINGS.adb_enabled}`);
                        return DEFAULT_GLOBAL_SETTINGS.adb_enabled;
                    case "auto_time":
                        log(`Settings.Global.getInt: ${name} -> ${DEFAULT_GLOBAL_SETTINGS.auto_time}`);
                        return DEFAULT_GLOBAL_SETTINGS.auto_time;
                    case "auto_time_zone":
                        log(`Settings.Global.getInt: ${name} -> ${DEFAULT_GLOBAL_SETTINGS.auto_time_zone}`);
                        return DEFAULT_GLOBAL_SETTINGS.auto_time_zone;
                    case "stay_on_while_plugged_in":
                        log(`Settings.Global.getInt: ${name} -> ${DEFAULT_GLOBAL_SETTINGS.stay_on_while_plugged_in}`);
                        return DEFAULT_GLOBAL_SETTINGS.stay_on_while_plugged_in;
                    case "mobile_data":
                        log(`Settings.Global.getInt: ${name} -> ${DEFAULT_GLOBAL_SETTINGS.mobile_data}`);
                        return DEFAULT_GLOBAL_SETTINGS.mobile_data;
                    case "airplane_mode_on":
                        log(`Settings.Global.getInt: ${name} -> ${DEFAULT_GLOBAL_SETTINGS.airplane_mode_on}`);
                        return DEFAULT_GLOBAL_SETTINGS.airplane_mode_on;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}