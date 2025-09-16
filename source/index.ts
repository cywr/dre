import * as Hooks from "./hooks";
import { Scratchpad } from "./scratchpad";
import { Logger } from "./utils/logger";
import Java from "frida-java-bridge";

if (Java.available) {
    Logger.setLogLevel(Logger.LogLevel.INFO)

    Java.performNow(() => {
        Hooks.Cloaking.perform()
        // Hooks.DCL.perform()
        // Hooks.Reflection.perform()
        // Hooks.SSLPinning.perform()
        // Hooks.SharedPreferences.perform()
        
        Hooks.Base64.perform()
        Hooks.Cipher.perform()
    });

    Java.perform(() => {
        

        Scratchpad.perform()
    })
}