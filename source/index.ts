import * as Hooks from "./hooks";
import { Scratchpad } from "./scratchpad";
import { Logger } from "./utils/logger";
import Java from "frida-java-bridge";

export const logLevel = Logger.LogLevel.INFO;
const logLevelNames = {
    [Logger.LogLevel.ERROR]: "ERROR",
    [Logger.LogLevel.INFO]: "INFO",
    [Logger.LogLevel.DEBUG]: "DEBUG",
    [Logger.LogLevel.VERBOSE]: "VERBOSE"
};

/**
 * https://www.piliapp.com/symbol/line/
 */

if (Java.available) {
    Java.perform(() => {
        Logger.setLogLevel(logLevel)

        Hooks.Cloaking.perform();
        Hooks.DevTools.perform();
        Hooks.Monitoring.perform();

        Scratchpad.perform();
    })
}