import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.app.ContextImpl class to monitor permission checks.
 */
export namespace ContextImpl {
    const NAME = "[ContextImpl]";
    const log = (message: string) => Logger.log(Logger.Type.Verbose, NAME, message);

    export function performNow(): void {
        try {
            const ContextImpl = Java.use("android.app.ContextImpl");

            ContextImpl.checkSelfPermission.overload("java.lang.String").implementation = function (permission: string) {
                const result = this.checkSelfPermission(permission);
                log(`Context.checkSelfPermission: ${permission} -> ${result}`);
                return result;
            };

            ContextImpl.checkPermission.overloads.forEach((overload: any) => {
                overload.implementation = function (...args: any) {
                    const result = this.checkPermission(...args);
                    log(`Context.checkPermission: ${args[0]} -> ${result}`);
                    return result;
                };
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}