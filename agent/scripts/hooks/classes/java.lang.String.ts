import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.lang.String class to bypass string-based detection.
 */
export namespace JavaLangString {
    const NAME = "[String]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            const String = Java.use('java.lang.String');
            
            String.contains.implementation = function(name:string) {
                switch(name) {
                    case "test-keys":
                        log(`String.contains: ${name} -> false`);
                        return false;
                    default:
                        return this.contains.call(this, name);
                        
                }
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}