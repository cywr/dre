import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.provider.Settings$Secure class to spoof secure settings.
 */
export namespace AndroidProviderSettingsSecure {
    const NAME = "[Settings.Secure]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    const spoofedDevice = {
        ANDROID_ID: "9774d56d682e549c"
    };

    export function performNow(): void {
        try {
            const SettingsSecure = Java.use("android.provider.Settings$Secure");

            // getString hooks
            SettingsSecure.getString.overload("android.content.ContentResolver", "java.lang.String").implementation = function (cr: any, name: string) {
                const ret = this.getString(cr, name);

                switch (name) {
                    case "android_id":
                        log(`Settings.Secure.getString: ${name} -> ${spoofedDevice.ANDROID_ID}`);
                        return spoofedDevice.ANDROID_ID;
                    case "mock_location":
                        log(`Settings.Secure.getString: ${name} -> 0`);
                        return "0";
                    default:
                        return ret;
                }
            };

            // getInt hooks
            SettingsSecure.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function (cr: any, name: string, defaultValue: number) {
                const ret = this.getInt(cr, name, defaultValue);

                switch (name) {
                    case "auto_time":
                        log(`Settings.Secure.getInt: ${name} -> 1`);
                        return 1;
                    case "development_settings_enabled":
                    case "adb_enabled":
                    case "airplane_mode_on":
                        log(`Settings.Secure.getInt: ${name} -> 0`);
                        return 0;
                    default:
                        return ret;
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}