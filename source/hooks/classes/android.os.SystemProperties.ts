import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for android.os.SystemProperties class to bypass system properties detection.
 */
export namespace SystemProperties {
    const NAME = "[SystemProperties]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function perform(): void {
        try {
            const SystemProperties = Java.use('android.os.SystemProperties');
            
            SystemProperties.get.overload('java.lang.String').implementation = function(name:string) {
                switch(name) {
                    case "ro.build.selinux":
                        log(`SystemProperties.get: ${name} -> 1`);
                        return "1";
                    case "ro.debuggable":
                        log(`SystemProperties.get: ${name} -> 0`);
                        return "0";
                    case "service.adb.root":
                        log(`SystemProperties.get: ${name} -> 0`);
                        return "0";
                    case "ro.secure":
                        log(`SystemProperties.get: ${name} -> 1`);
                        return "1";
                    default:
                        return this.get.call(this, name);
                        
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}