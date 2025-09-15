import { Logger } from "../../utils/logger";
import { Native } from "../tools/native";
import { ROOT_DETECTION_COMMANDS } from "../../utils/types/constants";

/**
 * Hook for native libc.so system() function to bypass native command execution detection.
 */
export namespace Libc {
    const NAME = "[libc]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function perform(): void {
        try {
            // Use the Native utility to hook system() function
            Native.attach({ 
                library: "libc.so", 
                method: "system",
                onEnter: function(args) {
                    const pointer = args[0];
                    const command = Native.readCString(pointer);
                    
                    if (!command) return;

                    // Check for root detection commands
                    const isRootDetection = ROOT_DETECTION_COMMANDS.some(cmd => 
                        command.includes(cmd) || command === cmd
                    );

                    if (isRootDetection) {
                        log(`Blocking root detection command: ${command}`);
                        pointer.writeUtf8String("grep"); // Replace with harmless command
                        return;
                    }

                    // Check for su command specifically
                    if (command === "su") {
                        log(`Blocking su command: ${command}`);
                        pointer.writeUtf8String("loremipsum"); // Replace with harmless command
                    }
                }
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}