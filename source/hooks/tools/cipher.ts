import { Logger } from "../../utils/logger";
import * as Utils from "../../utils/functions"
import Java from "frida-java-bridge";

/**
 * Intercepts calls of the core class of the Java Cryptographic Extension (JCE) framework (javax.crypto.Cipher)
 * Attempts to dump cryptographic parameters as well as the encryption/decryption data
 */
export namespace Cipher {
    const NAME = "[Cipher]";
    const log = (message: string) => Logger.log(Logger.Type.Hook, NAME, message);

    export function performNow(): void {
        try {
            init();
            final();
        } catch (error) {
            Logger.log(Logger.Type.Error, NAME, `Hooks failed: ${error}`);
        }
    }

    /**
     * Hooks on the initialization of Cipher instances.
     */
    function init() {
        const cipher = Java.use('javax.crypto.Cipher');
        
        cipher.init.overloads.forEach((overload: any) => {
            overload.implementation = function(...args: any) {
                var algorithm = this.getAlgorithm();
                var operation = "";
                var mode = args[0];
                var key = args[1];

                if (mode == 1)
                    operation = "Encrypting";
                else if (mode == 2)
                    operation = "Decrypting";

                let logMessage = `Instance initialized!!!\nAlgorithm: ${algorithm}\nOperation: ${operation}\nKey\n - Hex: ${Utils.bin2hex(key.getEncoded())}\n - ASCII: ${Utils.bin2ascii(key.getEncoded())}`;

                // Handle different parameter types (AlgorithmParameterSpec, AlgorithmParameters, etc.)
                if (args.length >= 3 && args[2]) {
                    try {
                        var param = Java.cast(args[2], Java.use('javax.crypto.spec.IvParameterSpec'));
                        logMessage += `\nIV\n - Hex: ${Utils.bin2hex(param.getIV())}`;
                    } catch (error) {
                        try {
                            var param = Java.cast(args[2], Java.use('javax.crypto.spec.GCMParameterSpec'));
                            logMessage += `\nIV\n - Hex: ${Utils.bin2hex(param.getIV())}`;
                        } catch (error2) {
                            // Other parameter types - skip IV logging
                        }
                    }
                }

                log(logMessage);
                return this.init(...args);
            };
        });
    }

    /**
     * Interception of inputs and outputs of executions.
     */
    function final() {
        const cipher = Java.use('javax.crypto.Cipher');
        
        cipher.doFinal.overloads.forEach((overload: any) => {
            overload.implementation = function(...args: any) {
                var outputByteArray = this.doFinal(...args);

                // Extract input byte array (always first argument)
                var inputByteArray = args[0];
                var inputHex = Utils.bin2hex(inputByteArray);
                var inputAscii = Utils.bin2ascii(inputByteArray);
                var outputHex = Utils.bin2hex(outputByteArray);
                var outputAscii = Utils.bin2ascii(outputByteArray);

                log( 
                    `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
                );

                return outputByteArray;
            };
        });
    }
}