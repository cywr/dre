import { Logger } from "../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.lang.ProcessBuilder class to bypass process execution detection.
 */
export namespace ProcessBuilder {
    const NAME = "[ProcessBuilder]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            const ProcessBuilder = Java.use('java.lang.ProcessBuilder');

            ProcessBuilder.start.implementation = function () {
                var cmd = this.command.call(this);
                var shouldModifyCommand = false;
                
                for (var i = 0; i < cmd.size(); i = i + 1) {
                    var tmp_cmd = cmd.get(i).toString();

                    if (tmp_cmd.indexOf("getprop") != -1 
                    || tmp_cmd.indexOf("mount") != -1 
                    || tmp_cmd.indexOf("build.prop") != -1 
                    || tmp_cmd.indexOf("id") != -1) {
                        shouldModifyCommand = true;
                    }
                }
                if (shouldModifyCommand) {
                    log(`ProcessBuilder.start: ${cmd}`);
                    this.command.call(this, ["grep"]);
                    return this.start.call(this);
                }
                if (cmd.indexOf("su") != -1) {
                    log(`ProcessBuilder.start: ${cmd}`);
                    this.command.call(this, ["loremipsum"]);
                    return this.start.call(this);
                }

                return this.start.call(this);
            };
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}