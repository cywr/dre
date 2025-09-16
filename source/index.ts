import * as Hooks from "./hooks";
import { Scratchpad } from "./scratchpad";
import { Logger } from "./utils/logger";
import Java from "frida-java-bridge";

if (Java.available) {
    Logger.setLogLevel(Logger.LogLevel.INFO)

    Java.perform(() => {
        // Hooks.Cloaking.perform();
        // Hooks.Monitoring.perform();

        Hooks.Cipher.perform()
        Hooks.Base64.perform()
        Hooks.DCL.perform()
        Hooks.Reflection.perform() // Re-enabled with safer implementation

        Scratchpad.perform();
    })
}