import { Logger } from "../../utils/logger";
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on runtime utilities for application behavior monitoring.
 */
export class Runtime extends Hook {
    NAME = "[Runtime]";
    LOG_TYPE = Logger.Type.Hook;

    info(): void {
        Logger.log(
            Logger.Type.Config, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └─┬\x1b[35m java.util.UUID \x1b[0m`
            + `\n║   └── randomUUID`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info();
        try {
            this.uuidHooks();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private UUID = Java.use("java.util.UUID");

    /**
     * Hooks UUID generation to monitor identifier creation.
     */
    uuidHooks() {
        const log = this.log;

        try {
            this.UUID.randomUUID.implementation = function() {
                const ret = this.randomUUID();
                
                // For some applications, consistent UUIDs might be needed
                // This is disabled by default to avoid breaking legitimate functionality
                
                log(`UUID.randomUUID: generated`);
                
                return ret;
                
                // Uncomment below to return consistent UUID:
                // const consistentUUID = "550e8400-e29b-41d4-a716-446655440000";
                // log(`UUID.randomUUID: returning consistent UUID`);
                // return Java.use("java.util.UUID").fromString(consistentUUID);
            };
        } catch (error) {
            log(`UUID hooks failed: ${error}`);
        }
    }
}