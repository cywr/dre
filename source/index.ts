import * as Hooks from "./hooks";
import { Scratchpad } from "./scratchpad";
import { Logger } from "./utils/logger";
import Java from "frida-java-bridge";

if (Java.available) {
    Logger.setLogLevel(Logger.LogLevel.INFO)

    Java.perform(() => {
        Hooks.Cloaking.perform()
        Hooks.SharedPreferences.perform()
        Hooks.SSLPinning.perform()

        Hooks.Base64.perform()
        Hooks.Cipher.perform()
        Hooks.DCL.perform()
        Hooks.Reflection.perform()
        Hooks.SSLPinning.perform()
        Hooks.SharedPreferences.perform()

        Scratchpad.perform()
    })
}