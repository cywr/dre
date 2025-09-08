import { Logger } from "../../utils/logger";
import { DEFAULT_SECURE_SETTINGS } from "../../utils/types";
import Java from "frida-java-bridge";

/**
 * Hook for android.provider.Settings$Secure class to spoof secure settings.
 */
export namespace SettingsSecure {
    const NAME = "[Settings.Secure]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const SettingsSecure = Java.use("android.provider.Settings$Secure");

            // getString hooks
            SettingsSecure.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function (cr: any, name: string) {
                const ret = this.getString(cr, name);

                switch (name) {
                    case "android_id":
                        log(`Settings.Secure.getString: ${name} -> ${DEFAULT_SECURE_SETTINGS.android_id}`);
                        return DEFAULT_SECURE_SETTINGS.android_id;
                    case "mock_location":
                        log(`Settings.Secure.getString: ${name} -> ${DEFAULT_SECURE_SETTINGS.mock_location}`);
                        return DEFAULT_SECURE_SETTINGS.mock_location;
                    default:
                        return ret;
                }
            };

            // getInt hooks
            SettingsSecure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, defaultValue: number) {
                const ret = this.getInt(cr, name, defaultValue);

                switch (name) {
                    case "auto_time":
                        log(`Settings.Secure.getInt: ${name} -> ${DEFAULT_SECURE_SETTINGS.auto_time}`);
                        return DEFAULT_SECURE_SETTINGS.auto_time;
                    case "development_settings_enabled":
                        log(`Settings.Secure.getInt: ${name} -> ${DEFAULT_SECURE_SETTINGS.development_settings_enabled}`);
                        return DEFAULT_SECURE_SETTINGS.development_settings_enabled;
                    case "adb_enabled":
                        log(`Settings.Secure.getInt: ${name} -> ${DEFAULT_SECURE_SETTINGS.adb_enabled}`);
                        return DEFAULT_SECURE_SETTINGS.adb_enabled;
                    case "airplane_mode_on":
                        log(`Settings.Secure.getInt: ${name} -> ${DEFAULT_SECURE_SETTINGS.airplane_mode_on}`);
                        return DEFAULT_SECURE_SETTINGS.airplane_mode_on;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}