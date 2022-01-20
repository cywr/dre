import { Logger } from "../../utils/logger";
import * as Utils from "../../utils/functions"
import { Hook } from "../../interfaces/hook";

/**
 * Intercepts calls of the core class of the Java Cryptographic Extension (JCE) framework (javax.crypto.Cipher)'
 * 'Attempts to dump cryptographic parameters as well as the encryption/decryption data'
 */
export class Cipher implements Hook {
    NAME = "[Cipher]"
    LOG_TYPE = Logger.Type.Hook

    info(): void {
        Logger.log(
            Logger.Type.Config, 
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
            this.init(this);
            this.final(this);
        } catch (error) {
            Logger.log(Logger.Type.Error, this.NAME, `Hooks failed: \n${error}`);
        }
    }

    /** Hooked classes */
    _cipher = Java.use('javax.crypto.Cipher');

    /**
     * Hooks on the initialization of Cipher instances.
     */
    init(_this:Cipher) {
        _this._cipher.init.overload('int', 'java.security.Key').implementation = function(mode: any, key: any) {
            var algorithm = this.getAlgorithm();
            var operation = "";

            if (mode == 1)
                operation = "Encrypting";
            else if (mode == 2)
                operation = "Decrypting";

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Instance initialized!!!\nAlgorithm: ${algorithm}\nOperation: ${operation}\nKey\n - Hex: ${Utils.bin2hex(key.getEncoded())}\n - ASCII: ${Utils.bin2ascii(key.getEncoded())}`
            );
            return this.init(mode, key);
        }

        _this._cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode: any, key: any, paramsec: any) {
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

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Instance initialized!!!\nAlgorithm: ${algorithm}\nOperation: ${operation}\nKey\n - Hex: ${Utils.bin2hex(key.getEncoded())}\n - ASCII: ${Utils.bin2ascii(key.getEncoded())}\nIV\n - Hex: ${Utils.bin2hex(param.getIV())}`
            );
            return this.init(mode, key, paramsec);
        }

        _this._cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom').implementation = function(mode: any, key: any, paramsec: any) {
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

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Instance initialized!!!\nAlgorithm: ${algorithm}\nOperation: ${operation}\nKey\n - Hex: ${Utils.bin2hex(key.getEncoded())}\n - ASCII: ${Utils.bin2ascii(key.getEncoded())}\nIV\n - Hex: ${Utils.bin2hex(param.getIV())}`
            );
            return this.init(mode, key, paramsec);
        }
    }

    /**
     * Interception of inputs and outputs of executions.
     */
    final(_this:Cipher) {
        _this._cipher.doFinal.overload('[B').implementation = function (inputByteArray: number[]) {
            var outputByteArray = this.doFinal(inputByteArray);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        _this._cipher.doFinal.overload('[B', 'int').implementation = function (inputByteArray: number[], outputOffset: any) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        _this._cipher.doFinal.overload('[B', 'int', 'int').implementation = function (inputByteArray: number[], outputOffset: number, inputlen: number) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset, inputlen);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        _this._cipher.doFinal.overload('[B', 'int', 'int', '[B').implementation = function (inputByteArray: number[], outputOffset: number, inputlen: number, output: number[]) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset, inputlen, output);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }

        _this._cipher.doFinal.overload('[B', 'int', 'int', '[B', 'int').implementation = function (inputByteArray: number[], outputOffset: number, inputlen: number, output: number[], outoffset: number) {
            var outputByteArray = this.doFinal(inputByteArray, outputOffset, inputlen, output, outoffset);

            var inputHex = Utils.bin2hex(inputByteArray);
            var inputAscii = Utils.bin2ascii(inputByteArray);
            var outputHex = Utils.bin2hex(outputByteArray);
            var outputAscii = Utils.bin2ascii(outputByteArray);

            Logger.log(_this.LOG_TYPE, _this.NAME, 
                `Execution!!!\nInput\n - Hex: ${inputHex}\n - ASCII: ${inputAscii}\nOutput\n - Hex: ${outputHex}\n - ASCII: ${outputAscii}`
            );

            return outputByteArray;
        }
    }
}