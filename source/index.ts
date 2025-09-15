import * as Hooks from "./hooks";
import { Scratchpad } from "./scratchpad";
import { Logger } from "./utils/logger";
import Java from "frida-java-bridge";

if (Java.available) {
    Logger.setLogLevel(Logger.LogLevel.INFO)

    Java.perform(() => {
        Hooks.Cloaking.perform();
        Hooks.Monitoring.perform();

        Scratchpad.perform();
    })
}