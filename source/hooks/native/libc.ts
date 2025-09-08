import { Logger } from "../../utils/logger";

/**
 * Hook for native libc.so system() function to bypass native command execution detection.
 */
export namespace Libc {
    const NAME = "[libc]";
    const log = (message: string) => Logger.log(Logger.Type.Debug, NAME, message);

    export function performNow(): void {
        try {
            Interceptor.attach((Module as any).findExportByName("libc.so", "system")!, {
                onEnter: function(args) {
                    var cmd = this.readCString(args[0]);

                    if (cmd.indexOf("getprop") != -1 
                    || cmd == "mount" 
                    || cmd.indexOf("build.prop") != -1 
                    || cmd == "id") {
                        log(`Native libc.so: ${cmd}`);
                        this.writeUtf8String(args[0], "grep");
                    }

                    if (cmd == "su") {
                        log(`Native libc.so: ${cmd}`);
                        this.writeUtf8String(args[0], "loremipsum");
                    }
                },
                onLeave: function(retval) {}
            });
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hook failed: ${error}`);
        }
    }
}