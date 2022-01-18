import { Logger } from "../../utils/logger";
import * as Utils from "../../utils/functions"

export namespace Encoding {
    const NAME = "[Encoding]";
    /**
     * Perform hooks on the system to intercept encodings.
     * 
     */
    export function hook() {
        Logger.log(Logger.Type.Config, NAME, "Hooks loaded.");
        try {
            base64()
        } catch(error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed.\n${error}`);
        }
    }

    function base64(){
        var Base64 = Java.use('android.util.Base64');

        //decode
        Base64.decode.overloads[0].implementation = function(endString:any, flags:any){
            var output = this.decode(endString,flags);
            Logger.log(Logger.Type.Hook, NAME, `Base64.decode\n - Input: ${endString}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        Base64.decode.overloads[1].implementation = function(byteString:any, flags:any){
            var output = this.decode(byteString,flags);
            Logger.log(Logger.Type.Hook, NAME, `Base64.decode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        Base64.decode.overloads[2].implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.decode(byteString,offset,ln,flags);
            Logger.log(Logger.Type.Hook, NAME, `Base64.decode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        //encode
        Base64.encode.overloads[0].implementation = function(byteString:any, flags:any){
            var output = this.encode(byteString,flags);
            Logger.log(Logger.Type.Hook, NAME, `Base64.encode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        Base64.encode.overloads[1].implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.encode(byteString,offset,ln,flags);
            Logger.log(Logger.Type.Hook, NAME, `Base64.encode\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${Utils.bin2ascii(output)}`);
            return output;
        }
        
        //encodeToString
        Base64.encodeToString.overload('[B', 'int').implementation = function(byteString:any, flags:any){
            var output = this.encodeToString(byteString,flags);
            Logger.log(Logger.Type.Hook, NAME, `Base64.encodeToString\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${output}`);
            return output;
        }
        
        Base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function(byteString:any, offset:any, ln:any, flags:any){
            var output = this.encodeToString(byteString,offset,ln,flags);
            Logger.log(Logger.Type.Hook, NAME, `Base64.encodeToString\n - Input: ${Utils.bin2ascii(byteString)}\n - Output: ${output}`);
            return output;
        }
    }
}
