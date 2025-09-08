import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.content.Intent class to spoof battery information and monitor intents.
 */
export namespace Intent {
    const NAME = "[Intent]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    const spoofedBattery = {
        level: 75,
        status: 2, // BATTERY_STATUS_CHARGING
        scale: 100,
        plugType: 1 // BATTERY_PLUGGED_AC
    };

    /**
     * Check if an intent is relevant and should be handled specially.
     */
    function isRelevantIntent(action: string, pkg: string, data: string): boolean {
        let isRelevant = false;
        if (pkg && pkg === "com.google.android.apps.maps") {
            isRelevant = true;
        }
        if (data && (data.startsWith("waze://?ll=") || data.startsWith("tel:"))) {
            isRelevant = true;
        }
        if (action && action.startsWith("android.intent.action.DIAL")) {
            isRelevant = true;
        }
        return isRelevant;
    }

    /**
     * Handle relevant intents for logging and analysis.
     */
    export function handleIntent(intent: any): boolean {
        try {
            const action = intent.getAction();
            const pkg = intent.getPackage();
            const data = intent.getDataString();
            let extrasString = "";
            const isIntentRelevant = isRelevantIntent(action, pkg, data);

            if (isIntentRelevant) {
                log("Relevant intent detected, logging details...");
                const extras = intent.getExtras();
                if (extras) {
                    try {
                        const keys = extras.keySet();
                        const iterator = keys.iterator();
                        while (iterator.hasNext()) {
                            const key = iterator.next().toString();
                            extrasString += intent.getStringExtra(key);
                        }
                    } catch (error) {
                        log(`Problem iterating extras: ${error}`);
                    }
                }
                
                log(`Intent details - Action: ${action}, Package: ${pkg}, Data: ${data}, Extras: ${extrasString}`);
            }

            return isIntentRelevant;
        } catch (error) {
            log(`handleIntent error: ${error}`);
            return false;
        }
    }

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
                        log(`Intent.resolveActivity called`);
                        handleIntent(this);
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