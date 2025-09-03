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
            Logger.Type.Config, 
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
        
        this.Base64.decode.overloads[0].implementation = function(endString:any, flags:any){
            var output = this.decode(endString,flags);
            log(`Base64.decode\n - Input: ${endString}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        this.Base64.decode.overloads[1].implementation = function(byteString:any, flags:any){
            var output = this.decode(byteString,flags);
            log(`Base64.decode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        this.Base64.decode.overloads[2].implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.decode(byteString,offset,ln,flags);
            log(`Base64.decode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
    }

    encode() {
        const log = this.log;
        
        this.Base64.encode.overloads[0].implementation = function(byteString:any, flags:any){
            var output = this.encode(byteString,flags);
            log(`Base64.encode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        this.Base64.encode.overloads[1].implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.encode(byteString,offset,ln,flags);
            log(`Base64.encode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        this.Base64.encodeToString.overload('[B', 'int').implementation = function(byteString:any, flags:any){
            var output = this.encodeToString(byteString,flags);
            log(`Base64.encodeToString\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${output}`);
            return output;
        }
        
        this.Base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.encodeToString(byteString,offset,ln,flags);
            log(`Base64.encodeToString\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${output}`);
            return output;
        }
    }
}
