import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.view.View class to control view background operations and resource usage.
 */
export namespace AndroidViewView {
    const NAME = "[View]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            cutResources();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Control view background methods to manage resource usage.
     */
    function cutResources(): void {
        try {
            const View = Java.use("android.view.View");
            
            try {
                View.setBackgroundColor.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setBackgroundColor blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setBackgroundColor hook failed: ${error}`);
            }

            try {
                View.setBackgroundResource.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setBackgroundResource blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setBackgroundResource hook failed: ${error}`);
            }

            try {
                View.setBackgroundDrawable.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        log(`setBackgroundDrawable blocked`);
                        return;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `setBackgroundDrawable hook failed: ${error}`);
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `cutResources failed: ${error}`);
        }
    }
}