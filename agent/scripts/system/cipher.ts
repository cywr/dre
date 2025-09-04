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
        
        this.cipher.init.overload('int', 'java.security.Key').implementation = function(mode: any, key: any) {
            var algorithm = this.getAlgorithm();
            var operation = "";

            if (mode == 1)
                operation = "Encrypting";
            else if (mode == 2)
                operation = "Decrypting";

            log(
                `Instance initialized!!!\nAlgorithm: ${algorithm}\nOperation: ${operation}\nKey\n - Hex: ${Utils.bin2hex(key.getEncoded())}\n - ASCII: ${Utils.bin2ascii(key.getEncoded())}`
            );
            return this.init(mode, key);
        }

        this.cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode: any, key: any, paramsec: any) {
            var algorithm = this.getAlgorithm();
            var operation = "";

            try {
                var param = Java.cast(paramsec, Java.use('javax.crypto.spec.IvParameterSpec'));    
            } catch (error) {
                var param = Java.cast(paramsec, Java.use('javax.crypto.spec.GCMParameterSpec'));
            }

            if (mode == 1)
                operation = "Encrypting";
            else if (mode == 2)
                operation = "Decrypting";

            log( 
                `Instance initialized!!!\nAlgorithm: ${algorithm}\nOperation: ${operation}\nKey\n - Hex: ${Utils.bin2hex(key.getEncoded())}\n - ASCII: ${Utils.bin2ascii(key.getEncoded())}\nIV\n - Hex: ${Utils.bin2hex(param.getIV())}`
            );
            return this.init(mode, key, paramsec);
        }

        this.cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom').implementation = function(mode: any, key: any, paramsec: any) {
            var algorithm = this.getAlgorithm();
            var operation = "";

            try {
                var param = Java.cast(paramsec, Java.use('javax.crypto.spec.IvParameterSpec'));    
            } catch (error) {
                var param = Java.cast(paramsec, Java.use('javax.crypto.spec.GCMParameterSpec'));
            }

            if (mode == 1)
                operation = "Encrypting";
            else if (mode == 2)
                operation = "Decrypting";

            log( 
                `Instance initialized!!!\nAlgorithm: ${algorithm}\nOperation: ${operation}\nKey\n - Hex: ${Utils.bin2hex(key.getEncoded())}\n - ASCII: ${Utils.bin2ascii(key.getEncoded())}\nIV\n - Hex: ${Utils.bin2hex(param.getIV())}`
            );
            return this.init(mode, key, paramsec);
        }
    }

    /**
     * Interception of inputs and outputs of executions.
     */
    final() {
        const log = this.log;
        
        this.cipher.doFinal.overload('[B').implementation = function (inputByteArray: number[]) {
            var outputByteArray = this.doFinal(inputByteArray);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            log( 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        this.cipher.doFinal.overload('[B', 'int').implementation = function (inputByteArray: number[], outputOffset: any) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            log( 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        this.cipher.doFinal.overload('[B', 'int', 'int').implementation = function (inputByteArray: number[], outputOffset: number, inputlen: number) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset, inputlen);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            log( 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        this.cipher.doFinal.overload('[B', 'int', 'int', '[B').implementation = function (inputByteArray: number[], outputOffset: number, inputlen: number, output: number[]) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset, inputlen, output);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            log( 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        this.cipher.doFinal.overload('[B', 'int', 'int', '[B', 'int').implementation = function (inputByteArray: number[], outputOffset: number, inputlen: number, output: number[], outoffset: number) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset, inputlen, output, outoffset);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            log( 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }
    }
}