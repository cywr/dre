import { Logger } from "./utils/logger";
import * as Utils from "./utils/functions"
import Java from "frida-java-bridge";
import { Native } from "./hooks/tools/native";

/**
 * Scratchpad namespace for testing experimental hooks.
 */
export namespace Scratchpad {
    const NAME = "[Scratchpad]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function perform(): void {
        native().catch(error => log(`Native test failed: ${error}`));
    }

    async function native(): Promise<void> {

        Native.waitLibrary("libmenascyber.so", async () => {
            await Native.listExports("libmenascyber.so");
            await Native.listImports("libmenascyber.so");

            await Native.attachMany([
                {
                    library: "libmenascyber.so",
                    method: "partthree_1",
                    onEnter: () => {
                        log("partthree_1 called");
                    },
                    onLeave: (retval) => {
                        log(`partthree_1 returned: ${retval}`);
                        log(`partthree_1 memory dump: ${Native.hexDump(retval, 16)}`);
                    }
                },
                {
                    library: "libmenascyber.so",
                    method: "partthree_2",
                    onEnter: () => {
                        log("partthree_2 called");
                    },
                    onLeave: (retval) => {
                        log(`partthree_2 returned: ${retval}`);
                        log(`partthree_2 memory dump: ${Native.hexDump(retval, 8)}`);
                    }
                }
            ]);

            await Native.call("libmenascyber.so", "partthree_1");
            await Native.call("libmenascyber.so", "partthree_2");
        });
    }
}