import { Logger } from "../../utils/logger";
import * as Utils from "../../utils/functions"
import { DexExtractor } from "../../utils/dexextractor";
import Java from "frida-java-bridge";

/**
 * Hook for android.util.Base64 class to intercept Base64 encoding/decoding operations.
 */
export namespace Base64 {
    const NAME = "[Base64]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function perform(): void {
        try {
            decode();
            encode();
        } catch(error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: ${error}`);
        }
    }

    function decode() {
        const Base64 = Java.use('android.util.Base64');
        
        Base64.decode.overloads.forEach((overload: any) => {
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
                
                // Check if output is DEX and extract if so
                if (DexExtractor.isDexFile(output)) {
                    DexExtractor.saveDexFile(output, "Base64", "decode");
                }
                
                return output;
            };
        });
    }

    function encode() {
        const Base64 = Java.use('android.util.Base64');
        
        Base64.encode.overloads.forEach((overload: any) => {
            overload.implementation = function(...args: any) {
                var output = this.encode(...args);
                log(`Base64.encode\n - Input: ${Utils.bin2ascii(args[0])}\n - Output: ${Utils.bin2ascii(output)}`);
                
                // Check if input or output is DEX and extract if so
                if (DexExtractor.isDexFile(args[0])) {
                    DexExtractor.saveDexFile(args[0], "Base64", "encode_input");
                }
                if (DexExtractor.isDexFile(output)) {
                    DexExtractor.saveDexFile(output, "Base64", "encode_output");
                }
                
                return output;
            };
        });
        
        Base64.encodeToString.overloads.forEach((overload: any) => {
            overload.implementation = function(...args: any) {
                var output = this.encodeToString(...args);
                log(`Base64.encodeToString\n - Input: ${Utils.bin2ascii(args[0])}\n - Output: ${output}`);
                
                // Check if input is DEX and extract if so
                if (DexExtractor.isDexFile(args[0])) {
                    DexExtractor.saveDexFile(args[0], "Base64", "encodeToString");
                }
                
                return output;
            };
        });
    }
}