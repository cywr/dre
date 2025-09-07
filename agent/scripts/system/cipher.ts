import { Logger } from "../../utils/logger";
import * as Utils from "../../utils/functions"
import { Hook } from "../../interfaces/hook";
import Java from "frida-java-bridge";

/**
 * Intercepts calls of the core class of the Java Cryptographic Extension (JCE) framework (javax.crypto.Cipher)'
 * 'Attempts to dump cryptographic parameters as well as the encryption/decryption data'
 */
export class Cipher extends Hook {
    NAME = "[Cipher]"
    LOG_TYPE = Logger.Type.Hook

    info(): void {
        Logger.log(
            Logger.Type.Debug, 
            this.NAME, `LogType: Hook`
            + `\n╓─┬\x1b[31m Java Classes \x1b[0m`
            + `\n║ └─┬\x1b[35m javax.crypto.Cipher \x1b[0m`
            + `\n║   ├── init`
            + `\n║   └── doFinal`
            + `\n╙────────────────────────────────────────────────────┘`
        );
    }
    
    execute(): void {
        this.info()
        try {
            this.init();
            this.final();
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    private cipher = Java.use('javax.crypto.Cipher');

    /**
     * Hooks on the initialization of Cipher instances.
     */
    init() {
        const log = this.log;
        
        this.cipher.init.overloads.forEach((overload: any) => {
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
    final() {
        const log = this.log;
        
        this.cipher.doFinal.overloads.forEach((overload: any) => {
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