import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.content.Context class to monitor permission checks and context operations.
 */
export namespace AndroidContentContext {
    const NAME = "[Context]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            antiEmulation();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Monitor permission checks and context operations for analysis.
     */
    function antiEmulation(): void {
        try {
            const ContextImpl = Java.use("android.app.ContextImpl");
            
            try {
                ContextImpl.checkSelfPermission.overload("java.lang.String").implementation = function (permission: any) {
                    const result = this.checkSelfPermission(permission);
                    log(`checkSelfPermission(${permission}) -> ${result}`);
                    return result;
                };
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `checkSelfPermission hook failed: ${error}`);
            }

            try {
                ContextImpl.checkPermission.overloads.forEach((overload: any) => {
                    overload.implementation = function (...args: any) {
                        const result = this.checkPermission(...args);
                        log(`checkPermission(${args}) -> ${result}`);
                        return result;
                    };
                });
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `checkPermission hook failed: ${error}`);
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `antiEmulation failed: ${error}`);
        }
    }
}