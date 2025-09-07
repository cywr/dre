import { Logger } from "../../utils/logger";
import * as Utils from "../../utils/functions"
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on the system to intercept encodings.
*/
export class Base64 extends Hook {
    NAME = "[Base64]";
    LOG_TYPE = Logger.Type.Hook;

    info(): void {
        Logger.log(
            Logger.Type.Debug, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └─┬\x1b[35m android.util.Base64 \x1b[0m`
            + `\n║   ├── decode`
            + `\n║   ├── encode`
            + `\n║   └── encodeToString`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }

    execute(): void {
        this.info()
        try {
            this.decode()
            this.encode()
        } catch(error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private Base64 = Java.use('android.util.Base64');

    decode() {
        const log = this.log;
        
        this.Base64.decode.overloads.forEach((overload: any) => {
            overload.implementation = function(...args: any) {
                var output = this.decode(...args);
                
                // Handle different argument patterns for logging
                if (args.length === 2) {
                    // decode(string/byte[], flags) - args[0] could be string or byte array
                    const input = typeof args[0] === 'string' ? args[0] : Utils.bin2ascii(args[0]);
                    log(`Base64.decode\n - Input: ${input}\n - Output: ${Utils.bin2ascii(output)}`);
                } else if (args.length === 4) {
                    // decode(byte[], offset, length, flags)
                    log(`Base64.decode\n - Input: ${Utils.bin2ascii(args[0])}\n - Output: ${Utils.bin2ascii(output)}`);
                }
                
                return output;
            };
        });
    }

    encode() {
        const log = this.log;
        
        this.Base64.encode.overloads.forEach((overload: any) => {
            overload.implementation = function(...args: any) {
                var output = this.encode(...args);
                log(`Base64.encode\n - Input: ${Utils.bin2ascii(args[0])}\n - Output: ${Utils.bin2ascii(output)}`);
                return output;
            };
        });
        
        this.Base64.encodeToString.overloads.forEach((overload: any) => {
            overload.implementation = function(...args: any) {
                var output = this.encodeToString(...args);
                log(`Base64.encodeToString\n - Input: ${Utils.bin2ascii(args[0])}\n - Output: ${output}`);
                return output;
            };
        });
    }
}
