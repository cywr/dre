import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.util.UUID class to manage UUID operations and DRM detection bypass.
 */
export namespace UUID {
    const NAME = "[UUID]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            antiEmulation();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }

    /**
     * Hook UUID operations to prevent DRM detection and bypass emulation checks.
     */
    function antiEmulation(): void {
        try {
            const UUID = Java.use("java.util.UUID");
            
            try {
                UUID.fromString.overload("java.lang.String").implementation = function(data: any) {
                    const result = this.fromString(data);
                    
                    switch (data) {
                        /**
                         * Replace Widevine CDM UUID with ClearKey CDM UUID
                         * This works with MediaDrm hooks to return a fake unique device ID.
                         */
                        case "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed":
                            log(`fromString(${data}) -> Returning ClearKey CDM UUID instead of Widevine CDM UUID`);
                            return this.fromString("1077efec-c0b2-4d02-ace3-3c1e52e2fb4b");
                        default:
                            break;
                    }
                    
                    log(`fromString(${data}) -> ${result.toString()}`);
                    return result;
                };
            } catch (error) {
                Logger.log(Logger.Type.Error, NAME, `fromString hook failed: ${error}`);
            }
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `antiEmulation failed: ${error}`);
        }
    }
}