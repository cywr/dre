import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.io.BufferedReader class to bypass test-keys detection.
 */
export namespace BufferedReader {
    const NAME = "[BufferedReader]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            const BufferedReader = Java.use('java.io.BufferedReader');

            BufferedReader.readLine.overloads.forEach((overload:any) => {
                overload.implementation = function (...args: any) {
                    var text = this.readLine.call(this, ...args);

                    if (text !== null && text.indexOf("ro.build.tags=test-keys") > -1) {
                        log(`BufferedReader.readLine: ${text} -> ro.build.tags=release-keys`);
                        text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                    }

                    return text;
                }
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}