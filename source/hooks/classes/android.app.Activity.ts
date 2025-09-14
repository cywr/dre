import { Logger } from "../../utils/logger";
import { Intent } from "./android.content.Intent";
import Java from "frida-java-bridge";

/**
 * Hook for android.app.Activity class to monitor activity launches and intent handling.
 */
export namespace Activity {
    const NAME = "[Activity]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function perform(): void {
        try {
            hookActivity();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Hook Activity.startActivity to monitor and potentially filter activity launches.
     */
    function hookActivity(): void {
        try {
            const Activity = Java.use("android.app.Activity");
            
            Activity.startActivity.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    try {
                        const intent = args[0];
                        log(`startActivity called with intent: ${intent}`);

                        if (!Intent.handleIntent(intent)) {
                            return this.startActivity(...args);
                        }
                    } catch (error) {
                        log(`startActivity monitoring error: ${error}`);
                    }
                };
            });

            Activity.finish.overloads.forEach((overload: any) => {
                overload.implementation = function () {
                    log("finish() - bypassing app termination");
                    return;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `hookActivity failed: ${error}`);
        }
    }
}