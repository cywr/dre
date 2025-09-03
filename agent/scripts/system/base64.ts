import { Logger } from "../../utils/logger";
import * as Utils from "../../utils/functions"
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Perform hooks on the system to intercept encodings.
*/
export class Base64 implements Hook {
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
            this.decode(this)
            this.encode(this)
        } catch(error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    /** Hooked classes */
    _Base64 = Java.use('android.util.Base64');

    decode(_this: Base64) {
        //decode
        _this._Base64.decode.overloads[0].implementation = function(endString:any, flags:any){
            var output = this.decode(endString,flags);
            Logger.log(_this.LOG_TYPE, _this.NAME, `Base64.decode\n - Input: ${endString}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        _this._Base64.decode.overloads[1].implementation = function(byteString:any, flags:any){
            var output = this.decode(byteString,flags);
            Logger.log(_this.LOG_TYPE, _this.NAME, `Base64.decode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        _this._Base64.decode.overloads[2].implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.decode(byteString,offset,ln,flags);
            Logger.log(_this.LOG_TYPE, _this.NAME, `Base64.decode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
    }

    encode(_this: Base64) {
        _this._Base64.encode.overloads[0].implementation = function(byteString:any, flags:any){
            var output = this.encode(byteString,flags);
            Logger.log(_this.LOG_TYPE, _this.NAME, `Base64.encode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        _this._Base64.encode.overloads[1].implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.encode(byteString,offset,ln,flags);
            Logger.log(_this.LOG_TYPE, _this.NAME, `Base64.encode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        _this._Base64.encodeToString.overload('[B', 'int').implementation = function(byteString:any, flags:any){
            var output = this.encodeToString(byteString,flags);
            Logger.log(_this.LOG_TYPE, _this.NAME, `Base64.encodeToString\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${output}`);
            return output;
        }
        
        _this._Base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.encodeToString(byteString,offset,ln,flags);
            Logger.log(_this.LOG_TYPE, _this.NAME, `Base64.encodeToString\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${output}`);
            return output;
        }
    }
}
