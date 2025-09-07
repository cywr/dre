import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.content.Intent class to spoof battery information and monitor intents.
 */
export namespace AndroidContentIntent {
    const NAME = "[Intent]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    const spoofedBattery = {
        level: 75,
        status: 2, // BATTERY_STATUS_CHARGING
        scale: 100,
        plugType: 1 // BATTERY_PLUGGED_AC
    };

    export function performNow(): void {
        try {
            const Intent = Java.use("android.content.Intent");

            // Hook getIntExtra for battery status spoofing
            Intent.getIntExtra.overload("java.lang.String", "int").implementation = function (name: string, defaultValue: number) {
                const ret = this.getIntExtra(name, defaultValue);
                const action = this.getAction();

                if (action === "android.intent.action.BATTERY_CHANGED") {
                    switch (name) {
                        case "level":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.level}`);
                            return spoofedBattery.level;
                        case "status":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.status}`);
                            return spoofedBattery.status;
                        case "scale":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.scale}`);
                            return spoofedBattery.scale;
                        case "plugged":
                            log(`Intent[BATTERY_CHANGED].getIntExtra: ${name} -> ${spoofedBattery.plugType}`);
                            return spoofedBattery.plugType;
                    }
                }

                return ret;
            };

            // Hook resolveActivity for intent monitoring
            Intent.resolveActivity.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    try {
                        const action = this.getAction();
                        const pkg = this.getPackage();
                        const data = this.getDataString();

                        if (action || pkg || data) {
                            log(`Intent.resolveActivity: ${action || 'no-action'} | ${pkg || 'no-pkg'} | ${data || 'no-data'}`);
                        }
                    } catch (error) {
                        log(`Intent.resolveActivity monitoring error: ${error}`);
                    }
                    return this.resolveActivity(...args);
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}