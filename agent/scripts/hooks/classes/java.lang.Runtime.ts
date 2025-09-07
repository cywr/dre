import { Logger } from "../../../utils/logger";
import Java from "frida-java-bridge";

/**
 * Hook for java.lang.Runtime class to bypass runtime execution detection.
 */
export namespace JavaLangRuntime {
    const NAME = "[Runtime]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            const Runtime = Java.use('java.lang.Runtime');
            
            Runtime.exec.overloads.forEach((overload:any) => {
                overload.implementation = function (...args: any) {
                    if (typeof args[0] === 'string' || args[0] instanceof String) {
                        var cmd = args[0].toString();

                        if ((cmd.indexOf("getprop") != -1)
                        || (cmd == "mount")
                        || (cmd.indexOf("build.prop") != -1)
                        || (cmd == "id")
                        || (cmd == "sh")) {
                            log(`Runtime.exec: ${cmd}`);
                            return this.exec.call(this, "grep");
                        }
                        if (cmd == "su") {
                            log(`Runtime.exec: ${cmd}`);
                            return this.exec.call(this, "loremipsum");
                        }

                        return this.exec.call(this, ...args);
                    } else {
                        var array = args[0];
                        
                        for (var i = 0; i < array.length; i = i + 1) {
                            var tmp_cmd = array[i];
            
                            if ((tmp_cmd.indexOf("getprop") != -1)
                            || (tmp_cmd == "mount")
                            || (tmp_cmd.indexOf("build.prop") != -1) 
                            || (tmp_cmd == "id") 
                            || (tmp_cmd == "sh")) {
                                log(`Runtime.exec: ${array}`);
                                return this.exec.call(this, "grep");
                            }
                            if (tmp_cmd == "su") {
                                log(`Runtime.exec: ${array}`);
                                return this.exec.call(this, "loremipsum");
                            }
                        }

                        return this.exec.call(this, ...args);
                    }
                }
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}